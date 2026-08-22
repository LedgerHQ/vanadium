//! Engine tests.
//!
//! Programs are assembled by hand from instruction words, so the engine is tested
//! without depending on the policy SDK or a compiler toolchain.

use alloc::{vec, vec::Vec};

use crate::policy::{
    host::{PolicyAttempt, PolicyCoords, PolicyHost},
    PolicyEngine, PolicyError, SigningDecision,
};

use super::image::test_util::ImageBuilder;
use super::image::{DATA_START, STACK_START};
use super::{abi, RiscvEngine};

// --------------------------------------------------------------------------
// A minimal RV32I assembler
// --------------------------------------------------------------------------

mod asm {
    pub const ZERO: u32 = 0;
    pub const SP: u32 = 2;
    pub const T0: u32 = 5;
    pub const T1: u32 = 6;
    pub const T2: u32 = 7;
    pub const S0: u32 = 8;
    pub const S1: u32 = 9;
    pub const A0: u32 = 10;
    pub const A1: u32 = 11;
    pub const A2: u32 = 12;

    fn i_type(imm: i32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
        ((imm as u32) & 0xFFF) << 20 | rs1 << 15 | funct3 << 12 | rd << 7 | opcode
    }

    pub fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
        i_type(imm, rs1, 0, rd, 0x13)
    }

    pub fn lw(rd: u32, rs1: u32, imm: i32) -> u32 {
        i_type(imm, rs1, 2, rd, 0x03)
    }

    pub fn sw(rs2: u32, rs1: u32, imm: i32) -> u32 {
        let imm = imm as u32;
        ((imm >> 5) & 0x7F) << 25 | rs2 << 20 | rs1 << 15 | 2 << 12 | (imm & 0x1F) << 7 | 0x23
    }

    pub fn add(rd: u32, rs1: u32, rs2: u32) -> u32 {
        rs2 << 20 | rs1 << 15 | rd << 7 | 0x33
    }

    pub fn sub(rd: u32, rs1: u32, rs2: u32) -> u32 {
        0x20 << 25 | rs2 << 20 | rs1 << 15 | rd << 7 | 0x33
    }

    /// `mv rd, rs`
    pub fn mv(rd: u32, rs: u32) -> u32 {
        add(rd, ZERO, rs)
    }

    pub fn lui(rd: u32, imm20: u32) -> u32 {
        (imm20 & 0xFFFFF) << 12 | rd << 7 | 0x37
    }

    /// `beq rs1, rs2, offset` — offset is relative to this instruction.
    pub fn beq(rs1: u32, rs2: u32, offset: i32) -> u32 {
        let imm = offset as u32;
        ((imm >> 12) & 1) << 31
            | ((imm >> 5) & 0x3F) << 25
            | rs2 << 20
            | rs1 << 15
            | ((imm >> 1) & 0xF) << 8
            | ((imm >> 11) & 1) << 7
            | 0x63
    }

    /// `j offset`
    pub fn jump(offset: i32) -> u32 {
        beq(ZERO, ZERO, offset)
    }

    pub const ECALL: u32 = 0x0000_0073;

    pub fn assemble(words: &[u32]) -> alloc::vec::Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }
}

use asm::*;

/// `exit(decision)`
fn exit_with(decision: u32) -> Vec<u32> {
    vec![
        addi(T0, ZERO, abi::EXIT as i32),
        addi(A0, ZERO, decision as i32),
        ECALL,
    ]
}

// --------------------------------------------------------------------------
// A mock host
// --------------------------------------------------------------------------

struct MockHost {
    attempts: Vec<PolicyAttempt>,
    tx_version: u32,
    locktime: u32,
    inputs: Vec<MockInput>,
    outputs: Vec<MockOutput>,
    inputs_total: u64,
    outputs_total: u64,
    raw_psbt: Vec<u8>,
    self_pubkeys: Vec<[u8; 33]>,
}

#[derive(Clone)]
struct MockInput {
    amount: u64,
    prevout: [u8; 36],
    sequence: u32,
    script_pubkey: Vec<u8>,
    flags: u32,
    account: Option<PolicyCoords>,
    taptree: Option<[u8; 32]>,
}

impl Default for MockInput {
    fn default() -> Self {
        Self {
            amount: 0,
            prevout: [0; 36],
            sequence: 0,
            script_pubkey: Vec::new(),
            flags: 0,
            account: None,
            taptree: None,
        }
    }
}

#[derive(Default, Clone)]
struct MockOutput {
    amount: u64,
    script_pubkey: Vec<u8>,
    flags: u32,
    account: Option<PolicyCoords>,
}

impl MockHost {
    fn new(attempts: Vec<PolicyAttempt>) -> Self {
        Self {
            attempts,
            tx_version: 2,
            locktime: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            inputs_total: 0,
            outputs_total: 0,
            raw_psbt: Vec::new(),
            self_pubkeys: Vec::new(),
        }
    }

    /// One attempt on input 0, the common shape.
    fn one_attempt() -> Self {
        Self::new(vec![PolicyAttempt {
            input_index: 0,
            placeholder_index: 0,
            is_musig: false,
        }])
    }

    /// No attempts: only the final call runs, so a program's verdict is observed
    /// unfolded.
    fn no_attempts() -> Self {
        Self::new(Vec::new())
    }
}

impl PolicyHost for MockHost {
    fn tx_version(&self) -> u32 {
        self.tx_version
    }
    fn locktime(&self) -> u32 {
        self.locktime
    }
    fn input_count(&self) -> u32 {
        self.inputs.len() as u32
    }
    fn output_count(&self) -> u32 {
        self.outputs.len() as u32
    }
    fn inputs_total(&self) -> u64 {
        self.inputs_total
    }
    fn outputs_total(&self) -> u64 {
        self.outputs_total
    }
    fn policy_hash(&self) -> [u8; 32] {
        [0xAB; 32]
    }
    fn attempts(&self) -> &[PolicyAttempt] {
        &self.attempts
    }
    fn self_pubkey(&self, k: u32) -> Option<[u8; 33]> {
        self.self_pubkeys.get(k as usize).copied()
    }
    fn input_amount(&self, i: u32) -> Option<u64> {
        self.inputs.get(i as usize).map(|x| x.amount)
    }
    fn input_prevout(&self, i: u32) -> Option<[u8; 36]> {
        self.inputs.get(i as usize).map(|x| x.prevout)
    }
    fn input_sequence(&self, i: u32) -> Option<u32> {
        self.inputs.get(i as usize).map(|x| x.sequence)
    }
    fn input_script_pubkey(&self, i: u32) -> Option<&[u8]> {
        self.inputs.get(i as usize).map(|x| x.script_pubkey.as_slice())
    }
    fn input_flags(&self, i: u32) -> Option<u32> {
        self.inputs.get(i as usize).map(|x| x.flags)
    }
    fn input_account(&self, i: u32) -> Option<Option<PolicyCoords>> {
        self.inputs.get(i as usize).map(|x| x.account)
    }
    fn input_taptree_hash(&self, i: u32) -> Option<Option<[u8; 32]>> {
        self.inputs.get(i as usize).map(|x| x.taptree)
    }
    fn output_amount(&self, i: u32) -> Option<u64> {
        self.outputs.get(i as usize).map(|x| x.amount)
    }
    fn output_script_pubkey(&self, i: u32) -> Option<&[u8]> {
        self.outputs
            .get(i as usize)
            .map(|x| x.script_pubkey.as_slice())
    }
    fn output_flags(&self, i: u32) -> Option<u32> {
        self.outputs.get(i as usize).map(|x| x.flags)
    }
    fn output_account(&self, i: u32) -> Option<Option<PolicyCoords>> {
        self.outputs.get(i as usize).map(|x| x.account)
    }
    fn raw_psbt(&self) -> &[u8] {
        &self.raw_psbt
    }
}

/// Assemble `words` into an image and evaluate it against `host`.
fn eval(words: &[u32], host: &mut MockHost) -> Result<SigningDecision, PolicyError> {
    let raw = ImageBuilder::new(assemble(words)).build();
    RiscvEngine::evaluate(&raw, host)
}

fn eval_with(
    build: impl FnOnce(&mut ImageBuilder),
    words: &[u32],
    host: &mut MockHost,
) -> Result<SigningDecision, PolicyError> {
    let mut b = ImageBuilder::new(assemble(words));
    build(&mut b);
    RiscvEngine::evaluate(&b.build(), host)
}

// --------------------------------------------------------------------------
// Decisions and folding
// --------------------------------------------------------------------------

#[test]
fn exits_with_each_decision() {
    for (encoded, expected) in [
        (0, SigningDecision::Deny),
        (1, SigningDecision::ApproveWithUserConfirmation),
        (2, SigningDecision::ApproveSilently),
    ] {
        let mut host = MockHost::no_attempts();
        assert_eq!(eval(&exit_with(encoded), &mut host), Ok(expected));
    }
}

#[test]
fn out_of_range_decision_is_a_fatal_error_not_a_refusal() {
    let mut host = MockHost::no_attempts();
    assert_eq!(
        eval(&exit_with(3), &mut host),
        Err(PolicyError::ExecutionFailed)
    );
}

/// A counter in the shared state makes each invocation observably different, which
/// is what lets the `min` fold be tested at all.
fn counting_program(state_off: i32) -> Vec<u32> {
    vec![
        lui(T1, 0x20),               // t1 = DATA_START
        lw(T2, T1, state_off),       // t2 = counter
        addi(T2, T2, 1),             // counter += 1
        sw(T2, T1, state_off),       // store it back
        addi(S0, ZERO, 2),           // s0 = 2
        sub(A0, S0, T2),             // a0 = 2 - counter
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ]
}

#[test]
fn shared_state_persists_across_invocations_and_verdicts_fold_with_min() {
    // One attempt, so two invocations. The counter yields 2-1=1 (Confirm) then
    // 2-2=0 (Deny), and min is Deny. Were the state reset, both would yield 1 and
    // the fold would produce Confirm — so this pins persistence and the fold at once.
    let mut host = MockHost::one_attempt();
    let state_off = (256 - 64) as i32; // data_len - state_len
    assert_eq!(
        eval(&counting_program(state_off), &mut host),
        Ok(SigningDecision::Deny)
    );
}

#[test]
fn shared_state_starts_zeroed() {
    // A single invocation sees counter 0, so 2-1 = 1.
    let mut host = MockHost::no_attempts();
    let state_off = (256 - 64) as i32;
    assert_eq!(
        eval(&counting_program(state_off), &mut host),
        Ok(SigningDecision::ApproveWithUserConfirmation)
    );
}

#[test]
fn bss_is_restored_before_every_invocation() {
    // Read a .bss word, then write 1 into it. Every invocation must read 0, so the
    // verdict is 2 - 0 = 2. If .bss leaked across invocations the second would read
    // 1 and fold the verdict down to Confirm.
    let words = vec![
        lui(T1, 0x20),     // t1 = DATA_START
        lw(T2, T1, 0),     // t2 = bss word (expected 0 every time)
        addi(S0, ZERO, 1),
        sw(S0, T1, 0),     // dirty it for the next invocation
        addi(S1, ZERO, 2),
        sub(A0, S1, T2),   // a0 = 2 - observed
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ];
    let mut host = MockHost::one_attempt();
    assert_eq!(eval(&words, &mut host), Ok(SigningDecision::ApproveSilently));
}

#[test]
fn stack_is_zeroed_before_every_invocation() {
    // Same shape, against a stack slot rather than .bss.
    let words = vec![
        lw(T2, SP, -16),
        addi(S0, ZERO, 1),
        sw(S0, SP, -16),
        addi(S1, ZERO, 2),
        sub(A0, S1, T2),
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ];
    let mut host = MockHost::one_attempt();
    assert_eq!(eval(&words, &mut host), Ok(SigningDecision::ApproveSilently));
}

#[test]
fn initialized_data_is_restored_before_every_invocation() {
    // .data holds 7. Each invocation reads it, then overwrites it with 1. Both
    // invocations must read 7, so the verdict stays Silent (7 is clamped by the
    // program to 2 via a compare).
    let words = vec![
        lui(T1, 0x20),
        lw(T2, T1, 0),      // must be 7 every time
        addi(S0, ZERO, 1),
        sw(S0, T1, 0),      // dirty it
        addi(S1, ZERO, 7),
        addi(A0, ZERO, 0),  // default Deny
        beq(T2, S1, 8),     // if it read 7, skip the jump
        jump(8),
        addi(A0, ZERO, 2),
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ];
    let mut host = MockHost::one_attempt();
    let mut data_init = 7u32.to_le_bytes().to_vec();
    data_init.resize(4, 0);
    assert_eq!(
        eval_with(|b| b.data_init = data_init.clone(), &words, &mut host),
        Ok(SigningDecision::ApproveSilently)
    );
}

// --------------------------------------------------------------------------
// Invocation arguments
// --------------------------------------------------------------------------

#[test]
fn attempt_arguments_arrive_in_registers() {
    // Exit with a0, which is the input index on an attempt call and NO_INPUT on the
    // final call. The final call is special-cased to exit Silent, so the folded
    // verdict is the attempt's input index: 1, i.e. Confirm.
    let words = vec![
        addi(T1, ZERO, -1),  // t1 = 0xFFFFFFFF = NO_INPUT
        beq(A0, T1, 12),     // final call -> exit(2)
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,               // exit(a0 = input_index)
        addi(A0, ZERO, 2),
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ];
    let mut host = MockHost::new(vec![PolicyAttempt {
        input_index: 1,
        placeholder_index: 0,
        is_musig: false,
    }]);
    assert_eq!(
        eval(&words, &mut host),
        Ok(SigningDecision::ApproveWithUserConfirmation)
    );
}

#[test]
fn attempt_count_is_passed_and_the_final_call_runs_last() {
    // Exit with a2 (attempt_count) on every invocation. With 2 attempts that is 2 on
    // all three invocations, so the fold stays Silent.
    let words = vec![
        mv(A0, A2),
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ];
    let attempt = |i| PolicyAttempt {
        input_index: i,
        placeholder_index: 0,
        is_musig: false,
    };
    let mut host = MockHost::new(vec![attempt(0), attempt(1)]);
    assert_eq!(eval(&words, &mut host), Ok(SigningDecision::ApproveSilently));
}

// --------------------------------------------------------------------------
// Traps and limits
// --------------------------------------------------------------------------

#[test]
fn an_infinite_loop_exhausts_the_budget() {
    let mut host = MockHost::no_attempts();
    let words = vec![jump(0)]; // branch to self
    assert_eq!(
        eval_with(
            |b| {
                b.step_budget_base = 500;
                b.step_budget_per_input = 0;
            },
            &words,
            &mut host
        ),
        Err(PolicyError::BudgetExhausted)
    );
}

#[test]
fn the_budget_is_shared_across_invocations() {
    // Each invocation costs 8 instructions. With 1 attempt there are 2 invocations,
    // so 12 steps is enough for the first but not the second: proof that the budget
    // is not reset per invocation.
    let state_off = (256 - 64) as i32;
    let mut host = MockHost::one_attempt();
    assert_eq!(
        eval_with(
            |b| {
                b.step_budget_base = 12;
                b.step_budget_per_input = 0;
            },
            &counting_program(state_off),
            &mut host
        ),
        Err(PolicyError::BudgetExhausted)
    );

    // Doubling it is enough for both.
    let mut host = MockHost::one_attempt();
    assert_eq!(
        eval_with(
            |b| {
                b.step_budget_base = 24;
                b.step_budget_per_input = 0;
            },
            &counting_program(state_off),
            &mut host
        ),
        Ok(SigningDecision::Deny)
    );
}

#[test]
fn running_off_the_end_of_the_code_fails() {
    // No EXIT: pc walks past code_len and the fetch faults.
    let mut host = MockHost::no_attempts();
    let words = vec![addi(ZERO, ZERO, 0), addi(ZERO, ZERO, 0)];
    assert_eq!(eval(&words, &mut host), Err(PolicyError::ExecutionFailed));
}

#[test]
fn an_unknown_ecall_fails() {
    let mut host = MockHost::no_attempts();
    let words = vec![addi(T0, ZERO, 0x7FF), ECALL];
    assert_eq!(eval(&words, &mut host), Err(PolicyError::ExecutionFailed));
}

#[test]
fn panic_fails() {
    let mut host = MockHost::no_attempts();
    let words = vec![
        addi(T0, ZERO, abi::PANIC as i32),
        addi(A0, ZERO, 0),
        addi(A1, ZERO, 0),
        ECALL,
    ];
    assert_eq!(eval(&words, &mut host), Err(PolicyError::ExecutionFailed));
}

#[test]
fn writing_to_the_code_segment_fails() {
    let mut host = MockHost::no_attempts();
    let words = vec![
        lui(T1, 0x10),        // t1 = CODE_START
        addi(T2, ZERO, 1),
        sw(T2, T1, 0),        // write into code
        addi(T0, ZERO, abi::EXIT as i32),
        addi(A0, ZERO, 2),
        ECALL,
    ];
    assert_eq!(eval(&words, &mut host), Err(PolicyError::ExecutionFailed));
}

#[test]
fn reading_unmapped_memory_fails() {
    let mut host = MockHost::no_attempts();
    let words = vec![
        lui(T1, 0x50),   // 0x50000: in no segment
        lw(T2, T1, 0),
        addi(T0, ZERO, abi::EXIT as i32),
        addi(A0, ZERO, 2),
        ECALL,
    ];
    assert_eq!(eval(&words, &mut host), Err(PolicyError::ExecutionFailed));
}

#[test]
fn an_out_of_bounds_output_buffer_fails() {
    // FEE writes 8 bytes; point it at the last 4 bytes of the data segment.
    let mut host = MockHost::no_attempts();
    let words = vec![
        lui(T1, 0x20),
        addi(A0, T1, (256 - 4) as i32),
        addi(T0, ZERO, abi::FEE as i32),
        ECALL,
        addi(T0, ZERO, abi::EXIT as i32),
        addi(A0, ZERO, 2),
        ECALL,
    ];
    assert_eq!(eval(&words, &mut host), Err(PolicyError::ExecutionFailed));
}

#[test]
fn validate_accepts_a_program_that_would_trap() {
    // Registration validates the image and must not execute it, so a program that
    // immediately faults still registers fine.
    let raw = ImageBuilder::new(assemble(&[addi(ZERO, ZERO, 0)])).build();
    assert_eq!(RiscvEngine::validate(&raw), Ok(()));

    let mut host = MockHost::no_attempts();
    assert_eq!(
        RiscvEngine::evaluate(&raw, &mut host),
        Err(PolicyError::ExecutionFailed)
    );
}

#[test]
fn validate_rejects_a_mismatched_abi_version() {
    let mut b = ImageBuilder::new(assemble(&exit_with(2)));
    b.abi_version = 1;
    assert_eq!(
        RiscvEngine::validate(&b.build()),
        Err(PolicyError::InvalidImage)
    );
}

// --------------------------------------------------------------------------
// Reading the transaction
// --------------------------------------------------------------------------

/// `t0 = call; ecall; exit(a0)` — exits with whatever the call returned.
fn exit_with_ecall_result(call: u32) -> Vec<u32> {
    vec![
        addi(T0, ZERO, call as i32),
        ECALL,
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ]
}

#[test]
fn reads_counts_through_ecalls() {
    let mut host = MockHost::no_attempts();
    host.inputs = vec![MockInput::default(); 2];
    host.outputs = vec![MockOutput::default(); 1];

    assert_eq!(
        eval(&exit_with_ecall_result(abi::INPUT_COUNT), &mut host),
        Ok(SigningDecision::ApproveSilently) // 2
    );
    assert_eq!(
        eval(&exit_with_ecall_result(abi::OUTPUT_COUNT), &mut host),
        Ok(SigningDecision::ApproveWithUserConfirmation) // 1
    );
    assert_eq!(
        eval(&exit_with_ecall_result(abi::TX_VERSION), &mut host),
        Ok(SigningDecision::ApproveSilently) // 2
    );
}

#[test]
fn reads_the_fee_through_a_pointer() {
    let mut host = MockHost::no_attempts();
    host.inputs_total = 1_000;
    host.outputs_total = 999; // fee == 1

    let words = vec![
        addi(A0, SP, -16),
        addi(T0, ZERO, abi::FEE as i32),
        ECALL,
        lw(A0, SP, -16),      // low word of the fee
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ];
    assert_eq!(
        eval(&words, &mut host),
        Ok(SigningDecision::ApproveWithUserConfirmation)
    );
}

#[test]
fn reads_totals_as_a_pair() {
    let mut host = MockHost::no_attempts();
    host.inputs_total = 2;
    host.outputs_total = 1;

    // TOTALS writes inputs_total then outputs_total; read the second one back.
    let words = vec![
        addi(A0, SP, -32),
        addi(T0, ZERO, abi::TOTALS as i32),
        ECALL,
        lw(A0, SP, -24),      // outputs_total low word
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ];
    assert_eq!(
        eval(&words, &mut host),
        Ok(SigningDecision::ApproveWithUserConfirmation)
    );
}

#[test]
fn reads_a_variable_length_script_and_reports_its_length() {
    let mut host = MockHost::no_attempts();
    host.outputs = vec![MockOutput {
        script_pubkey: vec![0xAA, 0xBB],
        ..Default::default()
    }];

    // OUTPUT_SCRIPT_PUBKEY(0, sp-16, 34) returns the length, which is 2.
    let words = vec![
        addi(A0, ZERO, 0),
        addi(A1, SP, -16),
        addi(A2, ZERO, 34),
        addi(T0, ZERO, abi::OUTPUT_SCRIPT_PUBKEY as i32),
        ECALL,
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ];
    assert_eq!(eval(&words, &mut host), Ok(SigningDecision::ApproveSilently));
}

#[test]
fn a_script_longer_than_the_buffer_fails_rather_than_truncating() {
    let mut host = MockHost::no_attempts();
    host.outputs = vec![MockOutput {
        script_pubkey: vec![0xAA; 34],
        ..Default::default()
    }];
    let words = vec![
        addi(A0, ZERO, 0),
        addi(A1, SP, -16),
        addi(A2, ZERO, 4), // too small
        addi(T0, ZERO, abi::OUTPUT_SCRIPT_PUBKEY as i32),
        ECALL,
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ];
    assert_eq!(eval(&words, &mut host), Err(PolicyError::ExecutionFailed));
}

#[test]
fn an_out_of_range_index_is_fatal() {
    let mut host = MockHost::no_attempts(); // no inputs at all
    let words = vec![
        addi(A0, ZERO, 0),
        addi(A1, SP, -16),
        addi(T0, ZERO, abi::INPUT_AMOUNT as i32),
        ECALL,
        addi(T0, ZERO, abi::EXIT as i32),
        addi(A0, ZERO, 2),
        ECALL,
    ];
    assert_eq!(eval(&words, &mut host), Err(PolicyError::ExecutionFailed));
}

#[test]
fn an_absent_account_reports_not_found_rather_than_failing() {
    let mut host = MockHost::no_attempts();
    host.inputs = vec![MockInput {
        account: None,
        ..Default::default()
    }];
    // INPUT_ACCOUNT returns NOT_FOUND; check it is not OK(0).
    let words = vec![
        addi(A0, ZERO, 0),
        addi(A1, SP, -16),
        addi(T0, ZERO, abi::INPUT_ACCOUNT as i32),
        ECALL,
        addi(T1, ZERO, -1), // NOT_FOUND
        addi(A0, ZERO, 0),
        beq(A0, T1, 8),     // never taken; placeholder to keep shapes uniform
        jump(8),
        addi(A0, ZERO, 0),
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ];
    // The interesting assertion is that it did not fail.
    assert_eq!(eval(&words, &mut host), Ok(SigningDecision::Deny));
}

#[test]
fn reads_account_coordinates_when_present() {
    let mut host = MockHost::no_attempts();
    host.inputs = vec![MockInput {
        account: Some(PolicyCoords {
            account_index: 0,
            is_change: true,
            address_index: 2,
        }),
        ..Default::default()
    }];
    // Coords is {account_index, is_change, address_index}; read address_index.
    let words = vec![
        addi(A0, ZERO, 0),
        addi(A1, SP, -16),
        addi(T0, ZERO, abi::INPUT_ACCOUNT as i32),
        ECALL,
        lw(A0, SP, -8), // address_index
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ];
    assert_eq!(eval(&words, &mut host), Ok(SigningDecision::ApproveSilently));
}

#[test]
fn self_pubkey_is_rejected_on_the_final_call() {
    // No attempts, so only the final call runs, where there is no current key.
    let mut host = MockHost::no_attempts();
    host.self_pubkeys = vec![[0x02; 33]];
    let words = vec![
        addi(A0, SP, -64),
        addi(T0, ZERO, abi::SELF_PUBKEY as i32),
        ECALL,
        addi(T0, ZERO, abi::EXIT as i32),
        addi(A0, ZERO, 2),
        ECALL,
    ];
    assert_eq!(eval(&words, &mut host), Err(PolicyError::ExecutionFailed));
}

#[test]
fn attempt_input_exposes_the_whole_attempt_set() {
    // ATTEMPT_INPUT(1) is the second attempt's input index, which is 2.
    let words = vec![
        addi(A0, ZERO, 1),
        addi(T0, ZERO, abi::ATTEMPT_INPUT as i32),
        ECALL,
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ];
    let attempt = |i| PolicyAttempt {
        input_index: i,
        placeholder_index: 0,
        is_musig: false,
    };
    let mut host = MockHost::new(vec![attempt(0), attempt(2)]);
    assert_eq!(eval(&words, &mut host), Ok(SigningDecision::ApproveSilently));
}

#[test]
fn psbt_read_returns_raw_bytes_and_clamps_at_the_end() {
    let mut host = MockHost::no_attempts();
    host.raw_psbt = vec![0x11, 0x22, 0x33];

    // PSBT_LEN is 3.
    assert_eq!(
        eval(&exit_with_ecall_result(abi::PSBT_LEN), &mut host),
        Err(PolicyError::ExecutionFailed) // 3 is not a valid decision
    );

    // PSBT_READ(offset=1, dst, len=8) returns 2, the bytes actually available.
    let words = vec![
        addi(A0, ZERO, 1),
        addi(A1, SP, -16),
        addi(A2, ZERO, 8),
        addi(T0, ZERO, abi::PSBT_READ as i32),
        ECALL,
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ];
    assert_eq!(eval(&words, &mut host), Ok(SigningDecision::ApproveSilently));
}

// --------------------------------------------------------------------------
// Accelerated calls
// --------------------------------------------------------------------------

#[test]
fn taptweak_pubkey_matches_the_apps_own_computation() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::key::{TapTweak, UntweakedPublicKey};
    use bitcoin::XOnlyPublicKey;

    // A valid x-only key: the x coordinate of the generator times 1.
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[0x11; 32]).unwrap();
    let (xonly, _) = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk).x_only_public_key();
    let internal: UntweakedPublicKey = XOnlyPublicKey::from_slice(&xonly.serialize()).unwrap();
    let (expected, _parity) = internal.tap_tweak(&secp, None);
    let expected = expected.serialize();
    let _ = bitcoin::TapNodeHash::all_zeros(); // keep the import honest

    // .data holds the input key at +0 and the expected first word at +32.
    let mut data_init = xonly.serialize().to_vec();
    data_init.extend_from_slice(&expected[..4]);

    let words = vec![
        lui(T1, 0x20),                              // t1 = DATA_START
        addi(T2, SP, -32),                          // out buffer
        mv(A0, T1),                                 // a0 = xonly ptr
        addi(A1, ZERO, 0),                          // a1 = null merkle root
        mv(A2, T2),                                 // a2 = out
        addi(T0, ZERO, abi::TAPTWEAK_PUBKEY as i32),
        ECALL,
        lw(S0, SP, -32),                            // first word of the result
        lw(S1, T1, 32),                             // first word expected
        addi(A0, ZERO, 0),                          // default Deny
        beq(S0, S1, 8),
        jump(8),
        addi(A0, ZERO, 2),                          // match -> Silent
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ];

    let mut host = MockHost::no_attempts();
    assert_eq!(
        eval_with(|b| b.data_init = data_init.clone(), &words, &mut host),
        Ok(SigningDecision::ApproveSilently)
    );
}

#[test]
fn sha256_matches_the_reference() {
    use bitcoin::hashes::Hash as _;

    let msg = b"vanadium";
    let expected = bitcoin::hashes::sha256::Hash::hash(msg).to_byte_array();

    // .data: message at +0 (8 bytes), expected first word at +8.
    let mut data_init = msg.to_vec();
    data_init.extend_from_slice(&expected[..4]);

    let words = vec![
        lui(T1, 0x20),
        mv(A0, T1),                          // data ptr
        addi(A1, ZERO, 8),                   // len
        addi(A2, SP, -64),                   // out
        addi(T0, ZERO, abi::SHA256 as i32),
        ECALL,
        lw(S0, SP, -64),
        lw(S1, T1, 8),
        addi(A0, ZERO, 0),
        beq(S0, S1, 8),
        jump(8),
        addi(A0, ZERO, 2),
        addi(T0, ZERO, abi::EXIT as i32),
        ECALL,
    ];

    let mut host = MockHost::no_attempts();
    assert_eq!(
        eval_with(|b| b.data_init = data_init.clone(), &words, &mut host),
        Ok(SigningDecision::ApproveSilently)
    );
}

#[test]
fn segment_bases_are_page_aligned() {
    use vanadium_common::constants::PAGE_SIZE;
    for base in [
        super::image::CODE_START,
        DATA_START,
        STACK_START,
    ] {
        assert_eq!(base as usize % PAGE_SIZE, 0, "base {base:#x} must be page aligned");
    }
}
