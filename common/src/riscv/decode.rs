use super::op::Op;

#[inline]
fn rd(inst: u32) -> u8 {
    ((inst >> 7) & 0b11111) as u8
}

#[inline]
fn rs1(inst: u32) -> u8 {
    ((inst >> 15) & 0b11111) as u8
}

#[inline]
fn rs2(inst: u32) -> u8 {
    ((inst >> 20) & 0b11111) as u8
}

#[inline]
fn b_imm(inst: u32) -> i32 {
    ((inst & 0b10000000_00000000_00000000_00000000) as i32) >> 19
        | ((inst & 0b00000000_00000000_00000000_10000000) as i32) << 4
        | ((inst & 0b01111110_00000000_00000000_00000000) as i32) >> 20
        | ((inst & 0b00000000_00000000_00001111_00000000) as i32) >> 7
}

#[inline]
fn i_imm(inst: u32) -> i32 {
    (inst as i32) >> 20
}

#[inline]
fn j_imm(inst: u32) -> i32 {
    ((inst & 0b10000000_00000000_00000000_00000000) as i32) >> 11
        | ((inst & 0b00000000_00001111_11110000_00000000) as i32) >> 0
        | ((inst & 0b00000000_00010000_00000000_00000000) as i32) >> 9
        | ((inst & 0b01111111_11100000_00000000_00000000) as i32) >> 20
}

#[inline]
fn s_imm(inst: u32) -> i32 {
    ((inst & 0b11111110_00000000_00000000_00000000) as i32) >> 20
        | ((inst & 0b00000000_00000000_00001111_10000000) as i32) >> 7
}

#[inline]
fn u_imm(inst: u32) -> i32 {
    (inst & 0xfffff000) as i32
}

// compressed instructions
mod rv32c {
    // This module contains the implementation of decoding of the Risc-V compressed instructions.
    // Each instruction is 16-bits, but it is expanded to a regular instructions during decoding.

    use super::Op;

    #[inline]
    fn c_rd(inst: u16) -> u8 {
        ((inst >> 7) & 0b11111) as u8
    }

    #[inline]
    fn c_rds(inst: u16) -> u8 {
        8 + ((inst >> 2) & 0b111) as u8
    }

    #[inline]
    fn c_rs1(inst: u16) -> u8 {
        ((inst >> 7) & 0b11111) as u8
    }

    #[inline]
    fn c_rs2(inst: u16) -> u8 {
        ((inst >> 2) & 0b11111) as u8
    }

    #[inline]
    fn c_rs1s(inst: u16) -> u8 {
        8 + ((inst >> 7) & 0b111) as u8
    }

    #[inline]
    fn c_rs2s(inst: u16) -> u8 {
        8 + ((inst >> 2) & 0b111) as u8
    }

    #[inline]
    fn c_funct3(inst: u16) -> u16 {
        ((inst >> 13) & 0b111) as u16
    }

    #[rustfmt::skip]
    #[inline]
    fn ci_imm(inst: u16) -> i32 {
          ((inst & 0b00010000_00000000) as i32) << 19 >> 26
        | ((inst & 0b00000000_01111100) as i32) >> 2
    }

    #[rustfmt::skip]
    #[inline]
    fn ci_addi16sp_imm(inst: u16) -> i32 {
          ((inst & 0b00010000_00000000) as i32) << 19 >> 22
        | ((inst & 0b00000000_00011000) as i32) << 4
        | ((inst & 0b00000000_00100000) as i32) << 1
        | ((inst & 0b00000000_00000100) as i32) << 3
        | ((inst & 0b00000000_01000000) as i32) >> 2
    }

    #[rustfmt::skip]
    #[inline]
    fn ci_lwsp_imm(inst: u16) -> i32 {
          ((inst & 0b00000000_00001100) as i32) << 4
        | ((inst & 0b00010000_00000000) as i32) >> 7
        | ((inst & 0b00000000_01110000) as i32) >> 2
    }

    #[rustfmt::skip]
    #[inline]
    fn css_swsp_imm(inst: u16) -> i32 {
          ((inst & 0b00000001_10000000) as i32) >> 1
        | ((inst & 0b00011110_00000000) as i32) >> 7
    }

    #[rustfmt::skip]
    #[inline]
    fn ciw_addi4spn_imm(inst: u16) -> u16 {
         ((inst & 0b00011000_00000000) >> 7
        | (inst & 0b00000111_10000000) >> 1
        | (inst & 0b00000000_01000000) >> 4
        | (inst & 0b00000000_00100000) >> 2) as u16
    }

    #[rustfmt::skip]
    #[inline]
    fn cl_lw_offset(inst: u16) -> i32 {
          ((inst & 0b00000000_00100000) as i32) << 1
        | ((inst & 0b00011100_00000000) as i32) >> 7
        | ((inst & 0b00000000_01000000) as i32) >> 4
    }

    #[inline]
    fn cs_sw_offset(inst: u16) -> i32 {
        cl_lw_offset(inst)
    }

    #[rustfmt::skip]
    #[inline]
    fn cb_imm(inst: u16) -> i32 {
          ((inst & 0b00010000_00000000) as i32) << 19 >> 23
        | ((inst & 0b00000000_01100000) as i32) << 1
        | ((inst & 0b00000000_00000100) as i32) << 3
        | ((inst & 0b00001100_00000000) as i32) >> 7
        | ((inst & 0b00000000_00011000) as i32) >> 2
    }

    #[rustfmt::skip]
    #[inline]
    fn cj_imm(inst: u16) -> i32 {
           ((inst & 0b00010000_00000000) as i32) << 19 >> 20
         | ((inst & 0b00000001_00000000) as i32) << 2
         | ((inst & 0b00000110_00000000) as i32) >> 1
         | ((inst & 0b00000000_01000000) as i32) << 1
         | ((inst & 0b00000000_10000000) as i32) >> 1
         | ((inst & 0b00000000_00000100) as i32) << 3
         | ((inst & 0b00001000_00000000) as i32) >> 7
         | ((inst & 0b00000000_00111000) as i32) >> 2
    }

    #[rustfmt::skip]
    #[inline]
    pub fn decode_compressed(inst: u16) -> Op {
        match inst & 0b11 {
            0b00 => {
                // Quadrant 0
                match c_funct3(inst) {
                    // C.ADDI4SPN
                    0b000 => {
                        let imm = ciw_addi4spn_imm(inst) as i32;
                        if imm == 0 {
                            Op::Unknown
                        } else {
                            Op::Addi { rd: c_rds(inst), rs1: 2, imm }
                        }
                    },
                    // C.LW
                    0b010 => Op::Lw { rd: c_rds(inst), rs1: c_rs1s(inst), imm: cl_lw_offset(inst) },
                    // C.SW
                    0b110 => Op::Sw { rs1: c_rs1s(inst), rs2: c_rs2s(inst), imm: cs_sw_offset(inst) },
                    _ => Op::Unknown,
                }
            }
            0b01 => {
                // Quadrant 1
                match c_funct3(inst) {
                    // C.ADDI
                    0b000 => Op::Addi { rd: c_rd(inst), rs1: c_rd(inst), imm: ci_imm(inst) },
                    // // C.JAL
                    // 0b001 => Op::Jal { rd: 1, imm: cj_imm(inst) },
                    // C.LI
                    0b010 => Op::Addi { rd: c_rd(inst), rs1: 0, imm: ci_imm(inst) },
                    0b011 => match c_rd(inst) {
                        // C.ADDI16SP
                        2 => {
                            let imm = ci_addi16sp_imm(inst);
                            if imm == 0 {
                                return Op::Unknown; // illegal (reserved)
                            }
                            Op::Addi { rd: 2, rs1: 2, imm }
                        },
                        // C.LUI
                        _ => Op::Lui { rd: c_rd(inst), imm: ci_imm(inst) << 12 },
                    },
                    0b100 => match (inst >> 10) & 0b11 {
                        // C.SRLI
                        0b00 => Op::Srli { rd: c_rs1s(inst), rs1: c_rs1s(inst), imm: ci_imm(inst) & 31 },
                        // C.SRAI
                        0b01 => Op::Srai { rd: c_rs1s(inst), rs1: c_rs1s(inst), imm: ci_imm(inst) & 31 },
                        // C.ANDI
                        0b10 => Op::Andi { rd: c_rs1s(inst), rs1: c_rs1s(inst), imm: ci_imm(inst) },
                        0b11 => match inst & 0x1000 {
                            0 => match (inst >> 5) & 0b11 {
                                // C.SUB
                                0b00 => Op::Sub { rd: c_rs1s(inst), rs1: c_rs1s(inst), rs2: c_rs2s(inst) },
                                // C.XOR
                                0b01 => Op::Xor { rd: c_rs1s(inst), rs1: c_rs1s(inst), rs2: c_rs2s(inst) },
                                // C.OR
                                0b10 => Op::Or { rd: c_rs1s(inst), rs1: c_rs1s(inst), rs2: c_rs2s(inst) },
                                // C.AND
                                0b11 => Op::And { rd: c_rs1s(inst), rs1: c_rs1s(inst), rs2: c_rs2s(inst) },
                                _ => unreachable!(),
                            },
                            _ => Op::Unknown,
                        }
                        _ => unreachable!(),
                    },
                    // C_J
                    0b101 => Op::Jal { rd: 0, imm: cj_imm(inst) },
                    // C_BEQZ
                    0b110 => Op::Beq { rs1: c_rs1s(inst), rs2: 0, imm: cb_imm(inst) },
                    // C_BNEZ
                    0b111 => Op::Bne { rs1: c_rs1s(inst), rs2: 0, imm: cb_imm(inst) },
                    _ => Op::Unknown,
                }
            }
            0b10 => {
                // Quadrant 2
                match c_funct3(inst) {
                    0b000 => match c_rd(inst) {
                        0 => Op::Unknown,
                        // C.SLLI
                        _ => Op::Slli { rd: c_rd(inst), rs1: c_rd(inst), imm: ci_imm(inst) & 31 },
                    },
                    0b010 => match c_rd(inst) {
                        0 => Op::Unknown,
                        // C.LWSP
                        _ => Op::Lw { rd: c_rd(inst), rs1: 2, imm: ci_lwsp_imm(inst) },
                    },
                    0b100 => match (inst >> 12) & 1 {
                        0 => match c_rs2(inst) {
                            0 => match c_rs1(inst) {
                                0 => Op::Unknown,
                                // C.JR
                                _ => Op::Jalr { rd: 0, rs1: c_rs1(inst), imm: 0 },
                            },
                            // C.MV
                            _ => Op::Add { rd: c_rd(inst), rs1: 0, rs2: c_rs2(inst) },
                        },
                        1 => match c_rs2(inst) {
                            0 => match c_rs1(inst) {
                                // C.EBREAK
                                0 => Op::Break,
                                // C.JALR
                                _ => Op::Jalr { rd: 1, rs1: c_rs1(inst), imm: 0 },
                            },
                            // C.ADD
                            _ => Op::Add { rd: c_rd(inst), rs1: c_rd(inst), rs2: c_rs2(inst) },
                        },
                        _ => unreachable!(),
                    },
                    // C.SWSP
                    0b110 => Op::Sw { rs1: 2, rs2: c_rs2(inst), imm: css_swsp_imm(inst) },
                    _ => Op::Unknown,
                }
            }
            _ => Op::Unknown,
        }
    }
}

#[rustfmt::skip]
#[inline]
fn decode_uncompressed(inst: u32) -> Op {
    match inst & 0x0000007f {
        0x00000037 => Op::Lui { rd: rd(inst), imm: u_imm(inst) },
        0x00000017 => Op::Auipc { rd: rd(inst), imm: u_imm(inst) },
        0x0000006f => Op::Jal { rd: rd(inst), imm: j_imm(inst) },
        0x00000067 => match inst & 0x0000707f {
            0x00000067 => Op::Jalr { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            _ => Op::Unknown,
        },
        0x00000063 => match inst & 0x0000707f {
            0x00000063 => Op::Beq { rs1: rs1(inst), rs2: rs2(inst), imm: b_imm(inst) },
            0x00001063 => Op::Bne { rs1: rs1(inst), rs2: rs2(inst), imm: b_imm(inst) },
            0x00004063 => Op::Blt { rs1: rs1(inst), rs2: rs2(inst), imm: b_imm(inst) },
            0x00005063 => Op::Bge { rs1: rs1(inst), rs2: rs2(inst), imm: b_imm(inst) },
            0x00006063 => Op::Bltu { rs1: rs1(inst), rs2: rs2(inst), imm: b_imm(inst) },
            0x00007063 => Op::Bgeu { rs1: rs1(inst), rs2: rs2(inst), imm: b_imm(inst) },
            _ => Op::Unknown,
        },
        0x00000003 => match inst & 0x0000707f {
            0x00000003 => Op::Lb { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00001003 => Op::Lh { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00002003 => Op::Lw { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00004003 => Op::Lbu { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00005003 => Op::Lhu { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            _ => Op::Unknown,
        },
        0x00000023 => match inst & 0x0000707f {
            0x00000023 => Op::Sb { rs1: rs1(inst), rs2: rs2(inst), imm: s_imm(inst) },
            0x00001023 => Op::Sh { rs1: rs1(inst), rs2: rs2(inst), imm: s_imm(inst) },
            0x00002023 => Op::Sw { rs1: rs1(inst), rs2: rs2(inst), imm: s_imm(inst) },
            _ => Op::Unknown,
        },
        0x00000013 => match inst & 0x0000707f {
            0x00000013 => Op::Addi { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00002013 => Op::Slti { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00003013 => Op::Sltiu { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00004013 => Op::Xori { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00006013 => Op::Ori { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00007013 => Op::Andi { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
            0x00001013 => match inst & 0xfe00707f {
                0x00001013 => Op::Slli { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
                _ => Op::Unknown,
            },
            0x00005013 => match inst & 0xfe00707f {
                0x00005013 => Op::Srli { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
                0x40005013 => Op::Srai { rd: rd(inst), rs1: rs1(inst), imm: i_imm(inst) },
                _ => Op::Unknown,
            },
            _ => Op::Unknown,
        },
        0x00000033 => match inst & 0xfe00707f {
            0x00000033 => Op::Add { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x40000033 => Op::Sub { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x00001033 => Op::Sll { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x00002033 => Op::Slt { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x00003033 => Op::Sltu { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x00004033 => Op::Xor { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x00005033 => Op::Srl { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x40005033 => Op::Sra { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x00006033 => Op::Or { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x00007033 => Op::And { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },            
            0x02000033 => Op::Mul { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x02001033 => Op::Mulh { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x02002033 => Op::Mulhsu { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x02003033 => Op::Mulhu { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x02004033 => Op::Div { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x02005033 => Op::Divu { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x02006033 => Op::Rem { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            0x02007033 => Op::Remu { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
            _ => Op::Unknown,
        },
        // RV32A - Atomic instructions (opcode 0x2F, funct3 = 0b010 for .W)
        0x0000002f => match inst & 0x0000707f {
            0x0000202f => match inst & 0xf800707f {
                0x1000202f => {
                    if rs2(inst) == 0 {
                        Op::LrW { rd: rd(inst), rs1: rs1(inst) }
                    } else {
                        Op::Unknown
                    }
                },
                0x1800202f => Op::ScW { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
                0x0800202f => Op::AmoswapW { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
                0x0000202f => Op::AmoaddW { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
                0x2000202f => Op::AmoxorW { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
                0x6000202f => Op::AmoandW { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
                0x4000202f => Op::AmoorW { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
                0x8000202f => Op::AmominW { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
                0xa000202f => Op::AmomaxW { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
                0xc000202f => Op::AmominuW { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
                0xe000202f => Op::AmomaxuW { rd: rd(inst), rs1: rs1(inst), rs2: rs2(inst) },
                _ => Op::Unknown,
            },
            _ => Op::Unknown,
        },
        // 0x0000000f => match inst & 0x0000707f {
        //     0x0000000f => match inst & 0xffffffff {
        //         0x8330000f => Op::RV_OP_FENCE_TSO,
        //         0x0100000f => Op::RV_OP_PAUSE,
        //         _ => Op::RV_OP_FENCE,
        //     },
        //     _ => Op::Unknown,
        // },
        0x00000073 => match inst & 0xffffffff {
            0x00000073 => Op::Ecall,
            0x00100073 => Op::Break,
            _ => Op::Unknown,
        },
        _ => Op::Unknown,
    }
}

#[inline]
pub fn decode(inst: u32) -> (Op, u32) {
    if inst & 0x3 != 0x3 {
        (rv32c::decode_compressed(inst as u16), 2)
    } else {
        (decode_uncompressed(inst), 4)
    }
}
