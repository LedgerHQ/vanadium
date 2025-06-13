#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

extern crate alloc;

use alloc::{format, vec, vec::Vec};
use sdk::{hash::Hasher, ux::Icon, App};
use serde::{Deserialize, Serialize};

sdk::bootstrap!();

#[derive(Clone)]
struct RPSGame {
    is_game_active: bool,
    c_a: [u8; 32], // Alice's commitment
    m_b: u8,       // our move
}

impl Default for RPSGame {
    fn default() -> Self {
        RPSGame {
            is_game_active: false,
            c_a: [0; 32],
            m_b: 0,
        }
    }
}

// create a global instance of the game state
// TODO: use proper state management system
static mut GAME_STATE: RPSGame = RPSGame {
    is_game_active: false,
    c_a: [0; 32],
    m_b: 0,
};

fn display_move(move_num: u8) -> &'static str {
    match move_num {
        0 => "Rock",
        1 => "Paper",
        2 => "Scissors",
        _ => panic!("Invalid move number: {}", move_num),
    }
}

// Shows the game summary and the app's chosen move
// Returns true if the user accepts
fn show_game_ui(c_a: &[u8; 32], m_b: u8) -> bool {
    sdk::ux::show_confirm_reject(
        "Game started",
        &format!(
            "Alice's commitment: {}\n\nWe'll play: {}",
            hex::encode(c_a),
            display_move(m_b)
        ),
        "Continue game",
        "Cancel",
    )
}

// Shows the game's outcome
fn show_game_result(m_a: u8, result: u8) {
    let alice_move = display_move(m_a);
    match result {
        0 => sdk::ux::show_info(
            Icon::None,
            &format!("It's a tie! Both played: {}", alice_move),
        ),
        1 => sdk::ux::show_info(
            Icon::Success,
            &format!("Alice played: {}\nWe win!", alice_move),
        ),
        2 => sdk::ux::show_info(
            Icon::Failure,
            &format!("Alice played: {}\nWe lose!", alice_move),
        ),
        _ => panic!("Invalid game result"),
    }
}

// generate a uniform random number in [0, 2]
fn random_move() -> u8 {
    loop {
        let byte = sdk::rand::random_bytes(1)[0];
        if byte != 255 {
            return byte % 3;
        }
        // Otherwise, retry to avoid modulo bias
    }
}

// Result:
// 0: tie
// 1: Alice wins
// 2: Bob wins
fn compute_winner(m_a: u8, m_b: u8) -> u8 {
    // 0 = Rock, 1 = Paper, 2 = Scissors
    match (m_a, m_b) {
        (0, 0) | (1, 1) | (2, 2) => 0, // Tie
        (0, 1) | (1, 2) | (2, 0) => 1, // Bob wins
        (0, 2) | (1, 0) | (2, 1) => 2, // Alice wins
        _ => panic!("Invalid game"),
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Command {
    Commit { c_a: [u8; 32] },
    Reveal { m_a: u8, r_a: [u8; 32] },
}

fn process_commit_command(c_a: [u8; 32]) -> Vec<u8> {
    // Generate a uniform random move in [0, 2]
    let m_b = random_move();

    // Create a new game
    let game_state = RPSGame {
        is_game_active: true,
        c_a, // Alice's commitment
        m_b, // our move
    };

    // store the game state to the global state
    unsafe { GAME_STATE = game_state };

    if show_game_ui(&c_a, m_b) {
        // Respond with our move
        vec![m_b]
    } else {
        // If the user rejects, we don't play
        vec![]
    }
}

fn process_reveal_command(m_a: u8, r_a: [u8; 32]) -> Vec<u8> {
    // copy the game state locally
    #[allow(static_mut_refs)] // forgive me, I have sinned
    let game_state = unsafe { GAME_STATE.clone() };

    if game_state.is_game_active == false {
        return vec![]; // No active game
    }

    if m_a > 2 {
        return vec![]; // Invalid move from Alice
    }

    // verify that SHA256(m_a || r_a) == c_a
    let mut sha = sdk::hash::Sha256::new();
    sha.update(&[m_a]);
    sha.update(&r_a);
    let computed_c_a = sha.finalize();

    if computed_c_a != game_state.c_a {
        return vec![]; // Invalid commitment
    }

    unsafe { GAME_STATE = RPSGame::default() }; // Reset the game state

    let winner = compute_winner(m_a, game_state.m_b);
    show_game_result(m_a, winner);

    vec![winner]
}

fn process_message(_app: &mut App, msg: &[u8]) -> Vec<u8> {
    if msg.is_empty() {
        sdk::exit(0);
    }

    let command: Command = match postcard::from_bytes(msg) {
        Ok(cmd) => cmd,
        Err(_) => return vec![], // Return an empty response on error
    };

    match command {
        Command::Commit { c_a } => process_commit_command(c_a),
        Command::Reveal { m_a, r_a } => process_reveal_command(m_a, r_a),
    }
}

pub fn main() {
    App::new(process_message).run();
}
