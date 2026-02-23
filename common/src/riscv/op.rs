#[derive(Debug, Copy, Clone)]
pub enum Op {
    Unknown,
    Add { rd: u8, rs1: u8, rs2: u8 },
    Sub { rd: u8, rs1: u8, rs2: u8 },
    Sll { rd: u8, rs1: u8, rs2: u8 },
    Slt { rd: u8, rs1: u8, rs2: u8 },
    Sltu { rd: u8, rs1: u8, rs2: u8 },
    Xor { rd: u8, rs1: u8, rs2: u8 },
    Srl { rd: u8, rs1: u8, rs2: u8 },
    Sra { rd: u8, rs1: u8, rs2: u8 },
    Or { rd: u8, rs1: u8, rs2: u8 },
    And { rd: u8, rs1: u8, rs2: u8 },
    Mul { rd: u8, rs1: u8, rs2: u8 },
    Mulh { rd: u8, rs1: u8, rs2: u8 },
    Mulhsu { rd: u8, rs1: u8, rs2: u8 },
    Mulhu { rd: u8, rs1: u8, rs2: u8 },
    Div { rd: u8, rs1: u8, rs2: u8 },
    Divu { rd: u8, rs1: u8, rs2: u8 },
    Rem { rd: u8, rs1: u8, rs2: u8 },
    Remu { rd: u8, rs1: u8, rs2: u8 },

    Addi { rd: u8, rs1: u8, imm: i32 },

    Andi { rd: u8, rs1: u8, imm: i32 },

    Auipc { rd: u8, imm: i32 },
    Beq { rs1: u8, rs2: u8, imm: i32 },
    Bne { rs1: u8, rs2: u8, imm: i32 },
    Blt { rs1: u8, rs2: u8, imm: i32 },
    Bge { rs1: u8, rs2: u8, imm: i32 },
    Bltu { rs1: u8, rs2: u8, imm: i32 },
    Bgeu { rs1: u8, rs2: u8, imm: i32 },
    Jal { rd: u8, imm: i32 },
    Jalr { rd: u8, rs1: u8, imm: i32 },

    Lb { rd: u8, rs1: u8, imm: i32 },
    Lh { rd: u8, rs1: u8, imm: i32 },
    Lw { rd: u8, rs1: u8, imm: i32 },
    Lbu { rd: u8, rs1: u8, imm: i32 },
    Lhu { rd: u8, rs1: u8, imm: i32 },

    Lui { rd: u8, imm: i32 },

    Ori { rd: u8, rs1: u8, imm: i32 },

    Sb { rs1: u8, rs2: u8, imm: i32 },
    Sh { rs1: u8, rs2: u8, imm: i32 },
    Sw { rs1: u8, rs2: u8, imm: i32 },

    Slli { rd: u8, rs1: u8, imm: i32 },
    Slti { rd: u8, rs1: u8, imm: i32 },
    Sltiu { rd: u8, rs1: u8, imm: i32 },
    Srli { rd: u8, rs1: u8, imm: i32 },
    Srai { rd: u8, rs1: u8, imm: i32 },

    Xori { rd: u8, rs1: u8, imm: i32 },

    // RV32A - Atomic instructions
    LrW { rd: u8, rs1: u8 },
    ScW { rd: u8, rs1: u8, rs2: u8 },
    AmoswapW { rd: u8, rs1: u8, rs2: u8 },
    AmoaddW { rd: u8, rs1: u8, rs2: u8 },
    AmoxorW { rd: u8, rs1: u8, rs2: u8 },
    AmoandW { rd: u8, rs1: u8, rs2: u8 },
    AmoorW { rd: u8, rs1: u8, rs2: u8 },
    AmominW { rd: u8, rs1: u8, rs2: u8 },
    AmomaxW { rd: u8, rs1: u8, rs2: u8 },
    AmominuW { rd: u8, rs1: u8, rs2: u8 },
    AmomaxuW { rd: u8, rs1: u8, rs2: u8 },

    Ecall,
    Break,
}
