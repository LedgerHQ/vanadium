#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use sdk::{executor::yield_now, ux::Icon, App, AppBuilder};

use client::Command;

sdk::bootstrap!();

/// Number of inner iterations per `do_work` call.
/// Tune this constant so that a single `do_work` call takes ~0.2 s.
const WORK_ITERATIONS: u32 = 100_000;

/// A single unit of pure local computation.
/// Performs `WORK_ITERATIONS` arithmetic steps on `value` and returns the result.
fn do_work(value: u64) -> u64 {
    let mut acc = value;
    sdk::println!("Doing work");
    for i in 0..WORK_ITERATIONS {
        acc = acc
            .wrapping_mul(6364136223846793061)
            .wrapping_add(i as u64 | 1);
    }
    acc
}

/// Calls `do_work` `n` times, chaining the output of each call as the input of the next.
fn compute_work(n: u32) -> Vec<u8> {
    let mut val: u64 = n as u64;
    for _ in 0..n {
        val = do_work(val);
    }
    val.to_le_bytes().to_vec()
}

/// Same computation as [`compute_work`], but yields periodically so the
/// executor can drive UX flows concurrently.
async fn compute_work_yielding(n: u32) -> Vec<u8> {
    let mut val: u64 = n as u64;
    for _ in 0..n {
        val = do_work(val);
        yield_now().await;
    }
    val.to_le_bytes().to_vec()
}

#[cfg(not(test))]
async fn show_ui(app: &mut App) -> bool {
    app.show_confirm_reject(
        "Do you want to do the thing?",
        "Make sure you want to do it.",
        "Do it!",
        "Reject",
    )
    .await
}

#[cfg(test)]
async fn show_ui(_app: &mut App) -> bool {
    true
}

/// Does all work first (blocking), then shows the UI.
async fn do_work_sync(app: &mut App, n: u32) -> Vec<u8> {
    app.show_spinner("Processing...");

    let result = compute_work(n);
    let approved = show_ui(app).await;

    if approved {
        app.show_info(Icon::Success, "The thing was done!");
        result
    } else {
        app.show_info(Icon::Failure, "No thing done.");
        vec![]
    }
}

/// Spawns work in a background task, shows the UI concurrently,
/// then waits for the worker to complete and shows a message.
async fn do_work_async(app: &mut App, n: u32) -> Vec<u8> {
    let handle = app.spawn_task(async move { compute_work_yielding(n).await });

    let approved = show_ui(app).await;

    if approved {
        let result = app.await_task("Processing...", handle);
        app.show_info(Icon::Success, "The thing was done!");
        result
    } else {
        drop(handle); // cancels the background task immediately
        app.show_info(Icon::Failure, "No thing done.");
        vec![]
    }
}

#[sdk::handler]
async fn process_message(app: &mut App, msg: &[u8]) -> Vec<u8> {
    if msg.is_empty() {
        sdk::exit(0);
    }

    let command: Command = match postcard::from_bytes(msg) {
        Ok(cmd) => cmd,
        Err(_) => return vec![], // Return an empty response on error
    };

    match command {
        Command::DoWorkSync { n } => do_work_sync(app, n).await,
        Command::DoWorkAsync { n } => do_work_async(app, n).await,
    }
}

pub fn main() {
    AppBuilder::new("Async", env!("CARGO_PKG_VERSION"), process_message)
        .description("Async Work Example")
        .run();
}
