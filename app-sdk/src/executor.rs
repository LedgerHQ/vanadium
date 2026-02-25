//! Cooperative single-threaded async executor for V-Apps.
//!
//! V-Apps run in a strictly single-threaded environment (one RISC-V core, no RTOS) so a
//! simple spin-loop executor without any thread-safe waker infrastructure is both correct
//! and efficient.
//!
//! # How it works
//!
//! 1. Background tasks are registered with [`spawn`].  Each task is a `'static` future
//!    that produces `()`.
//! 2. A "root" future (typically the entire message-handler flow for one request) is driven
//!    to completion by [`block_on`].
//! 3. Every time the root future returns `Poll::Pending`, `block_on` calls [`poll_once`] to
//!    advance all registered background tasks by one step.
//! 4. [`yield_now`] is a helper that yields `Poll::Pending` exactly once and then
//!    immediately completes.  Background tasks call it after each expensive step (e.g. after
//!    signing one input) to let the UX event loop run.
//!
//! A no-op waker ([`Waker::noop`]) is used because tasks are polled eagerly in every
//! `block_on` spin iteration – there is nothing to wake up.

use alloc::{boxed::Box, vec::Vec};
use core::{
    cell::RefCell,
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

// ---------------------------------------------------------------------------
// Task
// ---------------------------------------------------------------------------

struct Task(Pin<Box<dyn Future<Output = ()>>>);

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

/// A cooperative, `no_std` single-threaded executor.
pub struct Executor {
    tasks: Vec<Task>,
}

impl Executor {
    /// Creates an empty executor.
    pub const fn new() -> Self {
        Self { tasks: Vec::new() }
    }

    /// Adds a background task.  The future must be `'static`.
    pub fn spawn(&mut self, future: impl Future<Output = ()> + 'static) {
        self.tasks.push(Task(Box::pin(future)));
    }

    /// Polls every pending task once.  Completed tasks are dropped.
    fn poll_tasks(tasks: &mut Vec<Task>) {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(&waker);
        let mut i = 0;
        while i < tasks.len() {
            match tasks[i].0.as_mut().poll(&mut cx) {
                Poll::Ready(()) => {
                    // swap_remove is O(1); order among tasks does not matter.
                    tasks.swap_remove(i);
                }
                Poll::Pending => {
                    i += 1;
                }
            }
        }
    }

    /// Returns `true` if no background tasks are pending.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Global executor (single-threaded, no locking needed)
// ---------------------------------------------------------------------------

struct ExecutorCell(RefCell<Executor>);

// SAFETY: V-Apps are single-threaded; there is no concurrent access.
unsafe impl Sync for ExecutorCell {}

static GLOBAL_EXECUTOR: ExecutorCell = ExecutorCell(RefCell::new(Executor::new()));

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Registers a `'static` background future to be polled cooperatively inside
/// any active [`block_on`] call.
pub fn spawn(future: impl Future<Output = ()> + 'static) {
    GLOBAL_EXECUTOR.0.borrow_mut().spawn(future);
}

/// Advances all pending background tasks by one round of polling.
///
/// Tasks that call [`spawn`] during polling are picked up in the same round.
pub fn poll_once() {
    // Take the task list out of the RefCell so that tasks being polled can
    // re-entrantly call `spawn()` without hitting a double-borrow panic.
    let mut tasks = core::mem::take(&mut GLOBAL_EXECUTOR.0.borrow_mut().tasks);
    Executor::poll_tasks(&mut tasks);
    // Merge back: append any tasks that were spawned while we were polling.
    let mut exec = GLOBAL_EXECUTOR.0.borrow_mut();
    if exec.tasks.is_empty() {
        exec.tasks = tasks;
    } else {
        // New tasks were spawned during polling; keep them and append survivors.
        exec.tasks.append(&mut tasks);
    }
}

/// Drives `future` to completion, polling registered background tasks
/// ([`spawn`]-ed) on every `Poll::Pending` from the root future.
///
/// This is intentionally *not* re-entrant.  Nesting `block_on` calls will cause
/// the inner call to drive the same global executor, which may be surprising.
/// For V-App use there is typically only one active `block_on` call at a time.
///
/// # Important
///
/// The root future **must** eventually resolve through polling alone.  There is
/// no I/O reactor; if the root future and every background task return
/// `Poll::Pending` indefinitely the executor will spin forever.
pub fn block_on<T, F: Future<Output = T>>(future: F) -> T {
    // Pin the future on the stack; no heap allocation required.
    let mut future = core::pin::pin!(future);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(val) => return val,
            Poll::Pending => {
                poll_once();
            }
        }
    }
}

/// Yields control back to the executor, allowing other tasks and UX events
/// to be processed.
///
/// Background tasks performing substantial work should call this periodically
/// (e.g. every loop iteration or after processing each item) to keep the UI
/// responsive.
///
/// ```ignore
/// let handle = app.spawn_background(async {
///     for chunk in data.chunks(64) {
///         process(chunk);
///         yield_now().await;
///     }
///     result
/// });
/// ```
pub async fn yield_now() {
    pending_once().await;
}

/// Returns a future that yields [`Poll::Pending`] exactly once, then completes.
fn pending_once() -> impl Future<Output = ()> {
    let mut yielded = false;
    core::future::poll_fn(move |_cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            Poll::Pending
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use core::cell::Cell;

    #[test]
    fn block_on_immediately_ready() {
        let val = block_on(async { 42 });
        assert_eq!(val, 42);
    }

    #[test]
    fn yield_now_yields_then_completes() {
        let mut fut = core::pin::pin!(yield_now());
        let waker = Waker::noop();
        let mut cx = Context::from_waker(&waker);

        // First poll: Pending
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        // Second poll: Ready
        assert!(fut.as_mut().poll(&mut cx).is_ready());
    }

    #[test]
    fn spawn_and_poll_once_completes_task() {
        let done = Rc::new(Cell::new(false));
        let done2 = done.clone();

        let mut exec = Executor::new();
        exec.spawn(async move {
            done2.set(true);
        });

        assert!(!exec.is_empty());
        Executor::poll_tasks(&mut exec.tasks);
        assert!(exec.is_empty());
        assert!(done.get());
    }

    #[test]
    fn multiple_tasks_some_finish_early() {
        let finished = Rc::new(Cell::new(0u32));

        let mut exec = Executor::new();

        // Task 1: completes immediately
        let f = finished.clone();
        exec.spawn(async move {
            f.set(f.get() + 1);
        });

        // Task 2: yields once, then completes
        let f = finished.clone();
        exec.spawn(async move {
            yield_now().await;
            f.set(f.get() + 1);
        });

        // Task 3: completes immediately
        let f = finished.clone();
        exec.spawn(async move {
            f.set(f.get() + 1);
        });

        // First round: tasks 1 and 3 complete, task 2 yields
        Executor::poll_tasks(&mut exec.tasks);
        assert_eq!(exec.tasks.len(), 1);
        assert_eq!(finished.get(), 2);

        // Second round: task 2 completes
        Executor::poll_tasks(&mut exec.tasks);
        assert!(exec.is_empty());
        assert_eq!(finished.get(), 3);
    }

    #[test]
    fn block_on_with_background_task() {
        let result = Rc::new(Cell::new(0u32));
        let r = result.clone();

        // Spawn a background task that sets a value after yielding
        spawn(async move {
            yield_now().await;
            r.set(42);
        });

        // block_on a future that waits for the background task
        let r2 = result.clone();
        let val = block_on(async move {
            // Yield to let the background task run
            yield_now().await;
            // Yield once more; the background task should have completed
            yield_now().await;
            r2.get()
        });

        assert_eq!(val, 42);
    }

    #[test]
    fn reentrant_spawn_during_poll() {
        // Verify that a task can call spawn() during polling without panicking.
        let done = Rc::new(Cell::new(false));
        let done2 = done.clone();

        spawn(async move {
            // Spawn a new task from inside a running task
            spawn(async move {
                done2.set(true);
            });
        });

        // First poll_once: runs the outer task, which spawns the inner task
        poll_once();
        // Second poll_once: runs the inner task
        poll_once();
        assert!(done.get());
    }
}
