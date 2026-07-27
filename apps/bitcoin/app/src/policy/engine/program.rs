//! The built-in "signing program" language.
//!
//! A program is a tiny, infix, Rust-like script that runs for its *side effects*:
//!
//! ```text
//! if context.external_out_total > 5000000 { fail(); }
//! if context.external_out_total <= 100000 { approve(); }
//! ```
//!
//! Statements run top-to-bottom. The first action reached is terminal:
//! `fail()` → [`SigningDecision::Deny`], `approve()` → [`SigningDecision::ApproveSilently`].
//! Falling off the end → [`SigningDecision::ApproveWithUserConfirmation`]. Any
//! parse or runtime error (type mismatch, overflow, divide-by-zero, exceeded
//! limit) is reported to the caller, which fails closed.
//!
//! Grammar (see the crate design docs / `apps/bitcoin/docs/PSBT.md`):
//!
//! ```text
//! program := stmt*
//! stmt    := let_stmt | if_stmt | action ";"
//! let_stmt := "let" ident "=" expr ";"
//! if_stmt := "if" expr block ("else" (block | if_stmt))?
//! block   := "{" stmt* "}"
//! action  := ("fail" | "approve") "(" ")"
//! expr    := or ; or := and ("||" and)* ; and := cmp ("&&" cmp)*
//! cmp     := add (cmp_op add)?              ; comparisons are non-associative
//! add     := mul (("+"|"-") mul)* ; mul := unary (("*"|"/") unary)*
//! unary   := ("!"|"-") unary | primary
//! primary := int | "true" | "false" | "context" "." ident | ident | "(" expr ")"
//! cmp_op  := "==" | "!=" | "<" | "<=" | ">" | ">="
//! ```

use alloc::{boxed::Box, string::String, vec::Vec};

use common::psbt::signing_policy::ENGINE_ID_PROGRAM;

use crate::policy::{
    context::{Field, PolicyContext, Value},
    PolicyEngine, PolicyError, SigningDecision,
};

/// Maximum length of a program's source, in bytes.
const MAX_SOURCE_LEN: usize = 2048;
/// Maximum nesting depth of expressions and blocks (guards the recursive parser
/// and evaluator against stack exhaustion).
const MAX_DEPTH: usize = 32;

// ===================== Tokens =====================

#[derive(Debug, Clone, Copy, PartialEq)]
enum Token<'a> {
    If,
    Else,
    Let,
    True,
    False,
    Context,
    Ident(&'a str),
    Int(i64),
    LParen,
    RParen,
    LBrace,
    RBrace,
    Semi,
    Dot,
    AndAnd,
    OrOr,
    Bang,
    Assign,
    EqEq,
    BangEq,
    Lt,
    Le,
    Gt,
    Ge,
    Plus,
    Minus,
    Star,
    Slash,
}

fn is_ident_start(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphabetic()
}
fn is_ident_continue(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

fn tokenize(src: &[u8]) -> Result<Vec<Token<'_>>, PolicyError> {
    if src.len() > MAX_SOURCE_LEN {
        return Err(PolicyError::ProgramTooLarge);
    }
    let mut tokens = Vec::new();
    let mut i = 0usize;
    while i < src.len() {
        let b = src[i];
        match b {
            // whitespace
            b' ' | b'\t' | b'\r' | b'\n' => {
                i += 1;
            }
            b'(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            b')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            b'{' => {
                tokens.push(Token::LBrace);
                i += 1;
            }
            b'}' => {
                tokens.push(Token::RBrace);
                i += 1;
            }
            b';' => {
                tokens.push(Token::Semi);
                i += 1;
            }
            b'.' => {
                tokens.push(Token::Dot);
                i += 1;
            }
            b'+' => {
                tokens.push(Token::Plus);
                i += 1;
            }
            b'-' => {
                tokens.push(Token::Minus);
                i += 1;
            }
            b'*' => {
                tokens.push(Token::Star);
                i += 1;
            }
            b'/' => {
                if src.get(i + 1) == Some(&b'/') {
                    // line comment: skip to end of line
                    i += 2;
                    while i < src.len() && src[i] != b'\n' {
                        i += 1;
                    }
                } else {
                    tokens.push(Token::Slash);
                    i += 1;
                }
            }
            b'&' => {
                if src.get(i + 1) == Some(&b'&') {
                    tokens.push(Token::AndAnd);
                    i += 2;
                } else {
                    return Err(PolicyError::CompilationFailed);
                }
            }
            b'|' => {
                if src.get(i + 1) == Some(&b'|') {
                    tokens.push(Token::OrOr);
                    i += 2;
                } else {
                    return Err(PolicyError::CompilationFailed);
                }
            }
            b'!' => {
                if src.get(i + 1) == Some(&b'=') {
                    tokens.push(Token::BangEq);
                    i += 2;
                } else {
                    tokens.push(Token::Bang);
                    i += 1;
                }
            }
            b'=' => {
                if src.get(i + 1) == Some(&b'=') {
                    tokens.push(Token::EqEq);
                    i += 2;
                } else {
                    tokens.push(Token::Assign);
                    i += 1;
                }
            }
            b'<' => {
                if src.get(i + 1) == Some(&b'=') {
                    tokens.push(Token::Le);
                    i += 2;
                } else {
                    tokens.push(Token::Lt);
                    i += 1;
                }
            }
            b'>' => {
                if src.get(i + 1) == Some(&b'=') {
                    tokens.push(Token::Ge);
                    i += 2;
                } else {
                    tokens.push(Token::Gt);
                    i += 1;
                }
            }
            b'0'..=b'9' => {
                let start = i;
                while i < src.len() && src[i].is_ascii_digit() {
                    i += 1;
                }
                // Overflow-safe decimal parse.
                let mut acc: i64 = 0;
                for &d in &src[start..i] {
                    acc = acc
                        .checked_mul(10)
                        .and_then(|v| v.checked_add((d - b'0') as i64))
                        .ok_or(PolicyError::CompilationFailed)?;
                }
                tokens.push(Token::Int(acc));
            }
            _ if is_ident_start(b) => {
                let start = i;
                while i < src.len() && is_ident_continue(src[i]) {
                    i += 1;
                }
                let s = core::str::from_utf8(&src[start..i])
                    .map_err(|_| PolicyError::CompilationFailed)?;
                tokens.push(match s {
                    "if" => Token::If,
                    "else" => Token::Else,
                    "let" => Token::Let,
                    "true" => Token::True,
                    "false" => Token::False,
                    "context" => Token::Context,
                    other => Token::Ident(other),
                });
            }
            _ => return Err(PolicyError::CompilationFailed),
        }
    }
    Ok(tokens)
}

// ===================== AST =====================

#[derive(Debug, Clone, Copy, PartialEq)]
enum BinOp {
    And,
    Or,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Debug)]
enum Expr {
    Int(i64),
    Bool(bool),
    Field(Field),
    /// Reference to an in-scope `let` binding, by name.
    Var(String),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Action {
    Fail,
    Approve,
}

#[derive(Debug)]
enum Stmt {
    /// `let <name> = <value>;` — an immutable, block-scoped binding.
    Let {
        name: String,
        value: Expr,
    },
    If {
        cond: Expr,
        then_body: Vec<Stmt>,
        else_body: Vec<Stmt>,
    },
    Action(Action),
}

/// A compiled signing program.
#[derive(Debug)]
pub struct Program {
    body: Vec<Stmt>,
}

// ===================== Parser =====================

struct Parser<'a> {
    tokens: &'a [Token<'a>],
    pos: usize,
    /// Stack of lexical scopes; each holds the names declared in that block.
    /// Used to resolve variable references and reject undefined names, shadowing,
    /// and out-of-scope use at compile time.
    scopes: Vec<Vec<&'a str>>,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<Token<'a>> {
        self.tokens.get(self.pos).copied()
    }

    fn enter_scope(&mut self) {
        self.scopes.push(Vec::new());
    }

    fn leave_scope(&mut self) {
        self.scopes.pop();
    }

    /// Whether `name` is declared in any currently-open scope.
    fn is_visible(&self, name: &str) -> bool {
        self.scopes.iter().any(|s| s.iter().any(|&n| n == name))
    }

    /// Declare a new binding in the innermost scope. Rejects shadowing an
    /// already-visible name and re-using a reserved action name.
    fn declare(&mut self, name: &'a str) -> Result<(), PolicyError> {
        if name == "fail" || name == "approve" || self.is_visible(name) {
            return Err(PolicyError::CompilationFailed);
        }
        // A scope is always open while parsing statements.
        self.scopes
            .last_mut()
            .ok_or(PolicyError::CompilationFailed)?
            .push(name);
        Ok(())
    }

    fn next(&mut self) -> Option<Token<'a>> {
        let t = self.tokens.get(self.pos).copied();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, tok: Token<'a>) -> Result<(), PolicyError> {
        if self.next() == Some(tok) {
            Ok(())
        } else {
            Err(PolicyError::CompilationFailed)
        }
    }

    // ----- statements -----

    fn parse_program(&mut self) -> Result<Vec<Stmt>, PolicyError> {
        self.enter_scope();
        let body = self.parse_stmts(0)?;
        self.leave_scope();
        if self.pos != self.tokens.len() {
            return Err(PolicyError::CompilationFailed);
        }
        Ok(body)
    }

    /// Parse statements until EOF or a closing brace.
    fn parse_stmts(&mut self, depth: usize) -> Result<Vec<Stmt>, PolicyError> {
        if depth > MAX_DEPTH {
            return Err(PolicyError::ProgramTooLarge);
        }
        let mut stmts = Vec::new();
        loop {
            match self.peek() {
                None | Some(Token::RBrace) => break,
                _ => stmts.push(self.parse_stmt(depth)?),
            }
        }
        Ok(stmts)
    }

    fn parse_stmt(&mut self, depth: usize) -> Result<Stmt, PolicyError> {
        match self.peek() {
            Some(Token::If) => self.parse_if(depth),
            Some(Token::Let) => self.parse_let(depth),
            Some(Token::Ident(name)) => {
                // action call: `fail()` / `approve()` `;`
                self.pos += 1;
                let action = match name {
                    "fail" => Action::Fail,
                    "approve" => Action::Approve,
                    _ => return Err(PolicyError::CompilationFailed),
                };
                self.expect(Token::LParen)?;
                self.expect(Token::RParen)?;
                self.expect(Token::Semi)?;
                Ok(Stmt::Action(action))
            }
            _ => Err(PolicyError::CompilationFailed),
        }
    }

    fn parse_if(&mut self, depth: usize) -> Result<Stmt, PolicyError> {
        if depth > MAX_DEPTH {
            return Err(PolicyError::ProgramTooLarge);
        }
        self.expect(Token::If)?;
        let cond = self.parse_expr(depth)?;
        let then_body = self.parse_block(depth)?;
        let else_body = if self.peek() == Some(Token::Else) {
            self.pos += 1;
            if self.peek() == Some(Token::If) {
                // `else if` — parse as a nested if inside a synthetic block
                let nested = self.parse_if(depth + 1)?;
                let mut v = Vec::with_capacity(1);
                v.push(nested);
                v
            } else {
                self.parse_block(depth)?
            }
        } else {
            Vec::new()
        };
        Ok(Stmt::If {
            cond,
            then_body,
            else_body,
        })
    }

    fn parse_let(&mut self, depth: usize) -> Result<Stmt, PolicyError> {
        if depth > MAX_DEPTH {
            return Err(PolicyError::ProgramTooLarge);
        }
        self.expect(Token::Let)?;
        let name = match self.next() {
            Some(Token::Ident(n)) => n,
            _ => return Err(PolicyError::CompilationFailed),
        };
        self.expect(Token::Assign)?;
        let value = self.parse_expr(depth)?;
        self.expect(Token::Semi)?;
        // Declare only after parsing the value, so `let x = x;` is rejected
        // (no self-reference) and each binding sees only earlier ones.
        self.declare(name)?;
        Ok(Stmt::Let {
            name: name.into(),
            value,
        })
    }

    fn parse_block(&mut self, depth: usize) -> Result<Vec<Stmt>, PolicyError> {
        self.expect(Token::LBrace)?;
        self.enter_scope();
        let stmts = self.parse_stmts(depth + 1)?;
        self.leave_scope();
        self.expect(Token::RBrace)?;
        Ok(stmts)
    }

    // ----- expressions (precedence climbing) -----

    fn parse_expr(&mut self, depth: usize) -> Result<Expr, PolicyError> {
        self.parse_or(depth)
    }

    fn parse_or(&mut self, depth: usize) -> Result<Expr, PolicyError> {
        if depth > MAX_DEPTH {
            return Err(PolicyError::ProgramTooLarge);
        }
        let mut left = self.parse_and(depth + 1)?;
        while self.peek() == Some(Token::OrOr) {
            self.pos += 1;
            let right = self.parse_and(depth + 1)?;
            left = Expr::Bin(BinOp::Or, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self, depth: usize) -> Result<Expr, PolicyError> {
        if depth > MAX_DEPTH {
            return Err(PolicyError::ProgramTooLarge);
        }
        let mut left = self.parse_cmp(depth + 1)?;
        while self.peek() == Some(Token::AndAnd) {
            self.pos += 1;
            let right = self.parse_cmp(depth + 1)?;
            left = Expr::Bin(BinOp::And, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_cmp(&mut self, depth: usize) -> Result<Expr, PolicyError> {
        let left = self.parse_add(depth + 1)?;
        let op = match self.peek() {
            Some(Token::EqEq) => BinOp::Eq,
            Some(Token::BangEq) => BinOp::Ne,
            Some(Token::Lt) => BinOp::Lt,
            Some(Token::Le) => BinOp::Le,
            Some(Token::Gt) => BinOp::Gt,
            Some(Token::Ge) => BinOp::Ge,
            _ => return Ok(left),
        };
        self.pos += 1;
        // Non-associative: exactly one comparison.
        let right = self.parse_add(depth + 1)?;
        Ok(Expr::Bin(op, Box::new(left), Box::new(right)))
    }

    fn parse_add(&mut self, depth: usize) -> Result<Expr, PolicyError> {
        if depth > MAX_DEPTH {
            return Err(PolicyError::ProgramTooLarge);
        }
        let mut left = self.parse_mul(depth + 1)?;
        loop {
            let op = match self.peek() {
                Some(Token::Plus) => BinOp::Add,
                Some(Token::Minus) => BinOp::Sub,
                _ => break,
            };
            self.pos += 1;
            let right = self.parse_mul(depth + 1)?;
            left = Expr::Bin(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_mul(&mut self, depth: usize) -> Result<Expr, PolicyError> {
        if depth > MAX_DEPTH {
            return Err(PolicyError::ProgramTooLarge);
        }
        let mut left = self.parse_unary(depth + 1)?;
        loop {
            let op = match self.peek() {
                Some(Token::Star) => BinOp::Mul,
                Some(Token::Slash) => BinOp::Div,
                _ => break,
            };
            self.pos += 1;
            let right = self.parse_unary(depth + 1)?;
            left = Expr::Bin(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self, depth: usize) -> Result<Expr, PolicyError> {
        if depth > MAX_DEPTH {
            return Err(PolicyError::ProgramTooLarge);
        }
        match self.peek() {
            Some(Token::Bang) => {
                self.pos += 1;
                Ok(Expr::Not(Box::new(self.parse_unary(depth + 1)?)))
            }
            Some(Token::Minus) => {
                self.pos += 1;
                Ok(Expr::Neg(Box::new(self.parse_unary(depth + 1)?)))
            }
            _ => self.parse_primary(depth + 1),
        }
    }

    fn parse_primary(&mut self, depth: usize) -> Result<Expr, PolicyError> {
        if depth > MAX_DEPTH {
            return Err(PolicyError::ProgramTooLarge);
        }
        match self.next() {
            Some(Token::Int(n)) => Ok(Expr::Int(n)),
            Some(Token::True) => Ok(Expr::Bool(true)),
            Some(Token::False) => Ok(Expr::Bool(false)),
            Some(Token::LParen) => {
                let e = self.parse_expr(depth + 1)?;
                self.expect(Token::RParen)?;
                Ok(e)
            }
            Some(Token::Context) => {
                self.expect(Token::Dot)?;
                match self.next() {
                    Some(Token::Ident(name)) => {
                        let field = Field::from_name(name).ok_or(PolicyError::CompilationFailed)?;
                        Ok(Expr::Field(field))
                    }
                    _ => Err(PolicyError::CompilationFailed),
                }
            }
            // A bare identifier in expression position is a variable reference;
            // it must resolve to an in-scope `let` binding.
            Some(Token::Ident(name)) if self.is_visible(name) => Ok(Expr::Var(name.into())),
            _ => Err(PolicyError::CompilationFailed),
        }
    }
}

fn parse(src: &[u8]) -> Result<Program, PolicyError> {
    let tokens = tokenize(src)?;
    let mut parser = Parser {
        tokens: &tokens,
        pos: 0,
        scopes: Vec::new(),
    };
    let body = parser.parse_program()?;
    Ok(Program { body })
}

// ===================== Evaluation =====================

fn as_int(v: Value) -> Result<i64, PolicyError> {
    match v {
        Value::Int(n) => Ok(n),
        Value::Bool(_) => Err(PolicyError::ExecutionFailed),
    }
}

fn as_bool(v: Value) -> Result<bool, PolicyError> {
    match v {
        Value::Bool(b) => Ok(b),
        Value::Int(_) => Err(PolicyError::ExecutionFailed),
    }
}

fn eval_expr(
    expr: &Expr,
    ctx: &PolicyContext,
    env: &[(String, Value)],
    depth: usize,
) -> Result<Value, PolicyError> {
    if depth > MAX_DEPTH {
        return Err(PolicyError::ProgramTooLarge);
    }
    match expr {
        Expr::Int(n) => Ok(Value::Int(*n)),
        Expr::Bool(b) => Ok(Value::Bool(*b)),
        Expr::Field(f) => Ok(ctx.get(*f)),
        // Innermost binding wins (back-scan). Parse-time validation guarantees
        // the name is in scope; a miss is a defensive fail-closed.
        Expr::Var(name) => env
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, v)| *v)
            .ok_or(PolicyError::ExecutionFailed),
        Expr::Not(e) => Ok(Value::Bool(!as_bool(eval_expr(e, ctx, env, depth + 1)?)?)),
        Expr::Neg(e) => {
            let n = as_int(eval_expr(e, ctx, env, depth + 1)?)?;
            Ok(Value::Int(
                n.checked_neg().ok_or(PolicyError::ExecutionFailed)?,
            ))
        }
        Expr::Bin(op, a, b) => eval_bin(*op, a, b, ctx, env, depth),
    }
}

fn eval_bin(
    op: BinOp,
    a: &Expr,
    b: &Expr,
    ctx: &PolicyContext,
    env: &[(String, Value)],
    depth: usize,
) -> Result<Value, PolicyError> {
    // Short-circuiting boolean operators.
    match op {
        BinOp::And => {
            if !as_bool(eval_expr(a, ctx, env, depth + 1)?)? {
                return Ok(Value::Bool(false));
            }
            return Ok(Value::Bool(as_bool(eval_expr(b, ctx, env, depth + 1)?)?));
        }
        BinOp::Or => {
            if as_bool(eval_expr(a, ctx, env, depth + 1)?)? {
                return Ok(Value::Bool(true));
            }
            return Ok(Value::Bool(as_bool(eval_expr(b, ctx, env, depth + 1)?)?));
        }
        _ => {}
    }

    let va = eval_expr(a, ctx, env, depth + 1)?;
    let vb = eval_expr(b, ctx, env, depth + 1)?;

    match op {
        BinOp::Eq | BinOp::Ne => {
            let eq = match (va, vb) {
                (Value::Int(x), Value::Int(y)) => x == y,
                (Value::Bool(x), Value::Bool(y)) => x == y,
                _ => return Err(PolicyError::ExecutionFailed),
            };
            Ok(Value::Bool(if op == BinOp::Eq { eq } else { !eq }))
        }
        BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => {
            let x = as_int(va)?;
            let y = as_int(vb)?;
            let r = match op {
                BinOp::Lt => x < y,
                BinOp::Le => x <= y,
                BinOp::Gt => x > y,
                BinOp::Ge => x >= y,
                _ => unreachable!(),
            };
            Ok(Value::Bool(r))
        }
        BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div => {
            let x = as_int(va)?;
            let y = as_int(vb)?;
            let r = match op {
                BinOp::Add => x.checked_add(y),
                BinOp::Sub => x.checked_sub(y),
                BinOp::Mul => x.checked_mul(y),
                BinOp::Div => x.checked_div(y), // None on y == 0 or overflow
                _ => unreachable!(),
            };
            Ok(Value::Int(r.ok_or(PolicyError::ExecutionFailed)?))
        }
        BinOp::And | BinOp::Or => unreachable!(),
    }
}

/// Execute a block; returns `Some(decision)` if an action fired (terminal),
/// `None` if the block completed without an action.
fn exec_block(
    stmts: &[Stmt],
    ctx: &PolicyContext,
    env: &mut Vec<(String, Value)>,
) -> Result<Option<SigningDecision>, PolicyError> {
    let base = env.len();
    for stmt in stmts {
        match stmt {
            Stmt::Let { name, value } => {
                let v = eval_expr(value, ctx, env.as_slice(), 0)?;
                env.push((name.clone(), v));
            }
            Stmt::Action(Action::Fail) => return Ok(Some(SigningDecision::Deny)),
            Stmt::Action(Action::Approve) => return Ok(Some(SigningDecision::ApproveSilently)),
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                let branch = if as_bool(eval_expr(cond, ctx, env.as_slice(), 0)?)? {
                    then_body
                } else {
                    else_body
                };
                if let Some(decision) = exec_block(branch, ctx, env)? {
                    return Ok(Some(decision));
                }
            }
        }
    }
    // Drop bindings introduced by this block (block scoping). Terminal actions
    // above return early — the program is finished, so no cleanup is needed.
    env.truncate(base);
    Ok(None)
}

fn run(program: &Program, ctx: &PolicyContext) -> Result<SigningDecision, PolicyError> {
    let mut env: Vec<(String, Value)> = Vec::new();
    Ok(exec_block(&program.body, ctx, &mut env)?
        .unwrap_or(SigningDecision::ApproveWithUserConfirmation))
}

// ===================== Engine =====================

/// The built-in signing-program engine.
pub struct ProgramEngine;

impl PolicyEngine for ProgramEngine {
    const ENGINE_ID: u8 = ENGINE_ID_PROGRAM;
    const ENGINE_VERSION: u8 = 0;
    type Compiled = Program;

    fn compile(source: &[u8]) -> Result<Self::Compiled, PolicyError> {
        parse(source)
    }

    fn evaluate(
        program: &Self::Compiled,
        ctx: &PolicyContext,
    ) -> Result<SigningDecision, PolicyError> {
        run(program, ctx)
    }
}

// ===================== Tests =====================

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> PolicyContext {
        PolicyContext {
            inputs_total: 1_000_000,
            outputs_total: 950_000,
            internal_in_total: 1_000_000,
            external_out_total: 900_000,
            change_total: 50_000,
            fee: 50_000,
            fee_percent: 5,
            input_count: 2,
            output_count: 2,
            external_out_count: 1,
            change_count: 1,
            tx_version: 2,
            locktime: 0,
        }
    }

    fn eval(src: &str, c: &PolicyContext) -> Result<SigningDecision, PolicyError> {
        let p = parse(src.as_bytes())?;
        run(&p, c)
    }

    #[test]
    fn empty_program_falls_through() {
        assert_eq!(
            eval("", &ctx()),
            Ok(SigningDecision::ApproveWithUserConfirmation)
        );
    }

    #[test]
    fn bare_actions() {
        assert_eq!(eval("fail();", &ctx()), Ok(SigningDecision::Deny));
        assert_eq!(
            eval("approve();", &ctx()),
            Ok(SigningDecision::ApproveSilently)
        );
    }

    #[test]
    fn first_action_wins() {
        // approve fires before the later fail is reached
        let src = "approve(); fail();";
        assert_eq!(eval(src, &ctx()), Ok(SigningDecision::ApproveSilently));
    }

    #[test]
    fn spending_cap_silent() {
        let c = ctx();
        let src = "if context.external_out_total <= 1000000 { approve(); }";
        assert_eq!(eval(src, &c), Ok(SigningDecision::ApproveSilently));
        let src = "if context.external_out_total <= 100000 { approve(); }";
        assert_eq!(
            eval(src, &c),
            Ok(SigningDecision::ApproveWithUserConfirmation)
        );
    }

    #[test]
    fn hard_cap_deny() {
        let mut c = ctx();
        c.external_out_total = 6_000_000;
        let src = "if context.external_out_total > 5000000 { fail(); }";
        assert_eq!(eval(src, &c), Ok(SigningDecision::Deny));
    }

    #[test]
    fn fee_cap_or() {
        let mut c = ctx();
        c.fee = 60_000;
        c.fee_percent = 12;
        let src = "if context.fee > 50000 || context.fee_percent > 10 { fail(); }";
        assert_eq!(eval(src, &c), Ok(SigningDecision::Deny));
    }

    #[test]
    fn self_transfer_if_else() {
        let mut c = ctx();
        c.external_out_total = 0;
        let src = "if context.external_out_total == 0 { approve(); } else { fail(); }";
        assert_eq!(eval(src, &c), Ok(SigningDecision::ApproveSilently));
        c.external_out_total = 1;
        assert_eq!(eval(src, &c), Ok(SigningDecision::Deny));
    }

    #[test]
    fn not_operator() {
        // external_out_total = 900_000 → (== 0) is false → !false = true → fail
        let src = "if !(context.external_out_total == 0) { fail(); }";
        assert_eq!(eval(src, &ctx()), Ok(SigningDecision::Deny));
        // when fully internal, the guard does not fire
        let mut c = ctx();
        c.external_out_total = 0;
        assert_eq!(
            eval(src, &c),
            Ok(SigningDecision::ApproveWithUserConfirmation)
        );
    }

    #[test]
    fn arithmetic_percentage() {
        // fee must be under 1% of inputs: fee*100 > inputs_total -> fail
        let mut c = ctx();
        c.fee = 50_000; // 5% of 1_000_000
        c.inputs_total = 1_000_000;
        let src = "if context.fee * 100 > context.inputs_total { fail(); }";
        assert_eq!(eval(src, &c), Ok(SigningDecision::Deny));
        c.fee = 5_000; // 0.5%
        assert_eq!(
            eval(src, &c),
            Ok(SigningDecision::ApproveWithUserConfirmation)
        );
    }

    #[test]
    fn flagship_ordering() {
        let src = "\
            if context.fee > 50000 { fail(); }\n\
            if context.external_out_total > 5000000 { fail(); }\n\
            if context.external_out_total <= 100000 { approve(); }";
        let mut c = ctx();
        // small spend -> silent
        c.fee = 1000;
        c.external_out_total = 50_000;
        assert_eq!(eval(src, &c), Ok(SigningDecision::ApproveSilently));
        // medium spend -> normal approval (falls through)
        c.external_out_total = 1_000_000;
        assert_eq!(
            eval(src, &c),
            Ok(SigningDecision::ApproveWithUserConfirmation)
        );
        // over hard cap -> deny
        c.external_out_total = 6_000_000;
        assert_eq!(eval(src, &c), Ok(SigningDecision::Deny));
        // high fee -> deny (checked first)
        c.fee = 60_000;
        c.external_out_total = 50_000;
        assert_eq!(eval(src, &c), Ok(SigningDecision::Deny));
    }

    #[test]
    fn comments_and_whitespace() {
        let src =
            "// gate small spends\n if context.external_out_total <= 1000000 { approve(); } // ok";
        assert_eq!(eval(src, &ctx()), Ok(SigningDecision::ApproveSilently));
    }

    #[test]
    fn else_if_chain() {
        let src = "\
            if context.external_out_total > 5000000 { fail(); }\n\
            else if context.external_out_total <= 100000 { approve(); }";
        let mut c = ctx();
        c.external_out_total = 50_000;
        assert_eq!(eval(src, &c), Ok(SigningDecision::ApproveSilently));
        c.external_out_total = 6_000_000;
        assert_eq!(eval(src, &c), Ok(SigningDecision::Deny));
        c.external_out_total = 1_000_000;
        assert_eq!(
            eval(src, &c),
            Ok(SigningDecision::ApproveWithUserConfirmation)
        );
    }

    // ---- fail-closed / rejection paths ----

    #[test]
    fn rejects_unknown_field() {
        assert_eq!(
            parse(b"if context.nonexistent > 0 { fail(); }").err(),
            Some(PolicyError::CompilationFailed)
        );
    }

    #[test]
    fn rejects_unknown_action() {
        assert_eq!(
            parse(b"reject();").err(),
            Some(PolicyError::CompilationFailed)
        );
    }

    #[test]
    fn rejects_bad_syntax() {
        assert!(parse(b"if { fail(); }").is_err()); // missing condition
        assert!(parse(b"fail()").is_err()); // missing semicolon
        assert!(parse(b"fail();;").is_err()); // stray semicolon (empty stmt)
        assert!(parse(b"if true { fail(); } garbage").is_err());
        assert!(parse(b"context.fee").is_err()); // expression at statement position
        assert!(parse(b"1 & 2").is_err()); // single &
    }

    #[test]
    fn rejects_non_associative_comparison() {
        assert!(parse(b"if 1 < 2 < 3 { fail(); }").is_err());
    }

    #[test]
    fn runtime_type_mismatch_fails() {
        // adding an integer to a bool
        let p = parse(b"if true + 1 > 0 { fail(); }").unwrap();
        assert_eq!(run(&p, &ctx()), Err(PolicyError::ExecutionFailed));
    }

    #[test]
    fn divide_by_zero_fails() {
        let p = parse(b"if context.fee / context.locktime > 0 { fail(); }").unwrap();
        // locktime == 0 in the fixture
        assert_eq!(run(&p, &ctx()), Err(PolicyError::ExecutionFailed));
    }

    #[test]
    fn overflow_fails() {
        // inputs_total (1_000_000) * i64::MAX overflows.
        let p = parse(b"if context.inputs_total * 9223372036854775807 > 0 { fail(); }").unwrap();
        assert_eq!(run(&p, &ctx()), Err(PolicyError::ExecutionFailed));
    }

    #[test]
    fn oversized_source_rejected() {
        let mut src = alloc::string::String::new();
        for _ in 0..(MAX_SOURCE_LEN + 1) {
            src.push(' ');
        }
        assert_eq!(
            parse(src.as_bytes()).err(),
            Some(PolicyError::ProgramTooLarge)
        );
    }

    #[test]
    fn deep_nesting_rejected() {
        let mut src = alloc::string::String::new();
        for _ in 0..(MAX_DEPTH + 5) {
            src.push('(');
        }
        src.push('1');
        for _ in 0..(MAX_DEPTH + 5) {
            src.push(')');
        }
        // used in a statement so it parses far enough to hit the depth guard
        let full = alloc::format!("if {} > 0 {{ fail(); }}", src);
        assert_eq!(
            parse(full.as_bytes()).err(),
            Some(PolicyError::ProgramTooLarge)
        );
    }

    #[test]
    fn deep_operator_chain_fails_closed() {
        // Precedence parsing builds a flat chain into a left-nested AST without
        // increasing parser depth, so evaluation must enforce its own limit.
        let mut expr = alloc::string::String::from("0");
        for _ in 0..(MAX_DEPTH + 2) {
            expr.push_str(" + 1");
        }
        let src = alloc::format!("if {} > 0 {{ approve(); }}", expr);
        let program = parse(src.as_bytes()).unwrap();
        assert_eq!(run(&program, &ctx()), Err(PolicyError::ProgramTooLarge));
    }

    // ---- let bindings ----

    #[test]
    fn let_names_and_reuse() {
        // external_out_total = 900_000 in the fixture
        let src = "let spent = context.external_out_total;\n\
                   if spent > 5000000 { fail(); }\n\
                   if spent <= 1000000 { approve(); }";
        assert_eq!(eval(src, &ctx()), Ok(SigningDecision::ApproveSilently));
    }

    #[test]
    fn let_arithmetic() {
        // fee = 50_000; tenth of a 1_000_000 cap = 100_000 → fee < tenth → approve
        let src = "let cap = 1000000; let tenth = cap / 10; \
                   if context.fee < tenth { approve(); }";
        assert_eq!(eval(src, &ctx()), Ok(SigningDecision::ApproveSilently));
    }

    #[test]
    fn let_references_earlier_let() {
        let src = "let a = 5; let b = a + 5; if b == 10 { approve(); }";
        assert_eq!(eval(src, &ctx()), Ok(SigningDecision::ApproveSilently));
    }

    #[test]
    fn let_sibling_scopes_may_reuse_name() {
        // Two sibling blocks each bind `x`; only the first runs (fee == 50_000).
        let src = "if context.fee == 50000 { let x = 1; if x == 1 { approve(); } }\n\
                   if context.fee == 999   { let x = 2; if x == 2 { fail(); } }";
        assert_eq!(eval(src, &ctx()), Ok(SigningDecision::ApproveSilently));
    }

    #[test]
    fn let_out_of_scope_rejected() {
        // `x` is scoped to the first block; referencing it later is a compile error.
        assert_eq!(
            parse(b"if true { let x = 1; } if x == 1 { fail(); }").err(),
            Some(PolicyError::CompilationFailed)
        );
    }

    #[test]
    fn let_no_shadowing() {
        assert_eq!(
            parse(b"let x = 1; let x = 2;").err(),
            Some(PolicyError::CompilationFailed)
        );
        assert_eq!(
            parse(b"let x = 1; if true { let x = 2; }").err(),
            Some(PolicyError::CompilationFailed)
        );
    }

    #[test]
    fn let_undefined_variable_rejected() {
        assert_eq!(
            parse(b"if y == 0 { fail(); }").err(),
            Some(PolicyError::CompilationFailed)
        );
    }

    #[test]
    fn let_reserved_names_rejected() {
        assert_eq!(
            parse(b"let fail = 1;").err(),
            Some(PolicyError::CompilationFailed)
        );
        assert_eq!(
            parse(b"let approve = 1;").err(),
            Some(PolicyError::CompilationFailed)
        );
    }

    #[test]
    fn let_self_reference_rejected() {
        assert_eq!(
            parse(b"let x = x;").err(),
            Some(PolicyError::CompilationFailed)
        );
    }

    #[test]
    fn assign_vs_eq_still_distinct() {
        // `=` binds; `==` compares. Both present in one program.
        let src = "let n = 2; if n == context.output_count { approve(); }";
        assert_eq!(eval(src, &ctx()), Ok(SigningDecision::ApproveSilently));
    }
}
