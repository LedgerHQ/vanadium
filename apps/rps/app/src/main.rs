#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

extern crate alloc;

#[cfg(not(test))]
use alloc::format;
#[cfg(not(test))]
use sdk::ux::Icon;

use alloc::{vec, vec::Vec};
use sdk::{hash::Hasher, App, AppBuilder};
use serde::{Deserialize, Serialize};

sdk::bootstrap!();

#[derive(Clone, Default)]
struct RPSGame {
    is_game_active: bool,
    c_a: [u8; 32], // Alice's commitment
    m_b: u8,       // our move
}

#[cfg(not(test))]
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
#[cfg(not(test))]
fn show_game_ui(app: &mut App<RPSGame>, c_a: &[u8; 32], m_b: u8) -> bool {
    app.show_confirm_reject(
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

#[cfg(test)]
fn show_game_ui(_app: &mut App<RPSGame>, _c_a: &[u8; 32], _m_b: u8) -> bool {
    true
}

// Shows the game's outcome
#[cfg(not(test))]
fn show_game_result(app: &mut App<RPSGame>, m_a: u8, result: u8) {
    let alice_move = display_move(m_a);
    match result {
        0 => app.show_info(
            Icon::None,
            &format!("It's a tie! Both played: {}", alice_move),
        ),
        1 => app.show_info(
            Icon::Success,
            &format!("Alice played: {}\nWe win!", alice_move),
        ),
        2 => app.show_info(
            Icon::Failure,
            &format!("Alice played: {}\nWe lose!", alice_move),
        ),
        _ => panic!("Invalid game result"),
    }
}

#[cfg(test)]
fn show_game_result(_app: &mut App<RPSGame>, _m_a: u8, _result: u8) {}

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
// 1: Bob wins
// 2: Alice wins
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

fn process_commit_command(app: &mut App<RPSGame>, c_a: [u8; 32]) -> Vec<u8> {
    // Generate a uniform random move in [0, 2]
    let m_b = random_move();

    if show_game_ui(app, &c_a, m_b) {
        // Create a new game only if accepted
        app.state = RPSGame {
            is_game_active: true,
            c_a, // Alice's commitment
            m_b, // our move
        };
        vec![m_b]
    } else {
        // If the user rejects, we don't play
        vec![]
    }
}

fn process_reveal_command(app: &mut App<RPSGame>, m_a: u8, r_a: [u8; 32]) -> Vec<u8> {
    if !app.state.is_game_active {
        return vec![];
    }

    if m_a > 2 {
        return vec![]; // Invalid move from Alice
    }

    // verify that SHA256(m_a || r_a) == c_a
    let mut sha = sdk::hash::Sha256::new();
    sha.update(&[m_a]);
    sha.update(&r_a);
    let computed_c_a = sha.finalize();

    if computed_c_a != app.state.c_a {
        return vec![]; // Invalid commitment
    }

    let winner = compute_winner(m_a, app.state.m_b);
    show_game_result(app, m_a, winner);

    app.state = RPSGame::default(); // Reset the game state

    vec![winner]
}

fn process_message(app: &mut App<RPSGame>, msg: &[u8]) -> Vec<u8> {
    if msg.is_empty() {
        sdk::exit(0);
    }

    let command: Command = match postcard::from_bytes(msg) {
        Ok(cmd) => cmd,
        Err(_) => return vec![], // Return an empty response on error
    };

    match command {
        Command::Commit { c_a } => {
            let to_send = process_commit_command(app, c_a);
            if to_send.is_empty() {
                return vec![];
            }
            app.show_spinner("Waiting for Alice");
            let response = match app.exchange(&to_send) {
                Ok(resp) => resp,
                Err(_) => return vec![],
            };
            let reveal_command = match postcard::from_bytes::<Command>(&response) {
                Ok(cmd) => cmd,
                Err(_) => return vec![],
            };
            match reveal_command {
                Command::Reveal { m_a, r_a } => process_reveal_command(app, m_a, r_a),
                _ => panic!("Invalid command. Expected: Reveal"),
            }
        }
        _ => panic!("Invalid command. Expected: Commit"),
    }
}

pub fn main() {
    AppBuilder::<RPSGame>::new("RPS", env!("CARGO_PKG_VERSION"), process_message)
        .description("Rock-Paper-Scissors\n\nThe secure version")
        .run();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e2e() {
        let mut app = App::<RPSGame>::singleton();

        let r_a = [0x11u8; 32];
        let m_a = 1;
        let c_a = hex::decode("c2ad0a997751e04066912fa490a9976d6135d221c0df197dfb8c8a7a7e04da0e")
            .unwrap()
            .try_into()
            .unwrap();

        let res = process_commit_command(&mut app, c_a);
        assert!(res.len() == 1);
        let m_b = res[0];
        assert!(m_b <= 2, "Invalid move: {}", m_b);

        let winner = process_reveal_command(&mut app, m_a, r_a);
        assert!(
            winner.len() == 1,
            "Invalid response length: {}",
            winner.len()
        );
        let result = winner[0];
        assert!(result <= 2, "Invalid game result: {}", result);
        let expected_result = compute_winner(m_a, m_b);
        assert_eq!(
            result, expected_result,
            "Expected result: {}, got: {}",
            expected_result, result
        );
    }
}
