//! Work that several threads do at once.
//!
//! The library hands each batch of work to threads that are kept from one batch
//! to the next. A thread that is started for a batch costs tens of
//! microseconds before it does anything, and on Windows more, which every
//! batch of chunks would wait for. Lending work that borrows from its caller to
//! threads that are kept takes `unsafe` code, which rayon holds and this crate
//! does not.
//!
//! The threads are the library's own, not the pool that rayon shares with the
//! rest of a program. Much of what they do waits on a store, and a store may
//! wait on a disk or a network: work that waits is kept off a shared pool, so
//! that it holds up nothing else a program does there. And how many threads
//! the library uses is set by its own options, never by how a program sets up
//! rayon.

use rayon::{ThreadPool, ThreadPoolBuilder};
use std::sync::{Mutex, OnceLock, PoisonError};

/// How many threads the machine runs at once.
pub(crate) fn cores() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
}

/// The library's threads, one for each core, started the first time work is
/// handed to them. None if the system would not start them: then each batch
/// is done by the thread that asks for it.
fn pool() -> Option<&'static ThreadPool> {
    static POOL: OnceLock<Option<ThreadPool>> = OnceLock::new();
    POOL.get_or_init(|| {
        ThreadPoolBuilder::new()
            .num_threads(cores())
            .thread_name(|number| format!("scionic-{number}"))
            .build()
            .ok()
    })
    .as_ref()
}

/// Runs `work` on `others` of the library's threads, and on this thread once
/// `meanwhile` is done, and gives what each run of `work` gave, with what
/// `meanwhile` gave. It returns once every run is done. A panic in any of them
/// is raised here then, as a thread's panic is raised where it is joined.
pub(crate) fn with_helpers<T: Send, U>(
    others: usize,
    work: &(impl Fn() -> T + Sync),
    meanwhile: impl FnOnce() -> U,
) -> (Vec<T>, U) {
    let pool = match pool() {
        Some(pool) if others > 0 => pool,
        // With no thread to help, this one does it all.
        _ => {
            let done = meanwhile();
            return (vec![work()], done);
        }
    };
    let given = Mutex::new(Vec::with_capacity(others));
    let (own, done) = pool.in_place_scope(|scope| {
        for _ in 0..others {
            scope.spawn(|_| {
                let got = work();
                given
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(got);
            });
        }
        let done = meanwhile();
        (work(), done)
    });
    let mut all = given.into_inner().unwrap_or_else(PoisonError::into_inner);
    all.push(own);
    (all, done)
}

/// Runs `work` on `threads` threads at once, this one among them, and gives
/// what each run gave.
pub(crate) fn on_threads<T: Send>(threads: usize, work: &(impl Fn() -> T + Sync)) -> Vec<T> {
    with_helpers(threads.saturating_sub(1), work, || ()).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn every_run_is_given_back_and_meanwhile_runs_on_this_thread() {
        let runs = AtomicUsize::new(0);
        let here = std::thread::current().id();
        let (given, there) = with_helpers(7, &|| runs.fetch_add(1, Ordering::Relaxed), || {
            std::thread::current().id()
        });
        let mut given = given;
        given.sort_unstable();
        assert_eq!(given, (0..8).collect::<Vec<_>>());
        assert_eq!(there, here);
        assert_eq!(on_threads(0, &|| 1), vec![1]);
        assert_eq!(on_threads(3, &|| 1), vec![1, 1, 1]);
    }

    #[test]
    fn a_panic_on_a_thread_of_the_pool_is_raised_here_once_all_are_done() {
        let done = AtomicUsize::new(0);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            on_threads(4, &|| {
                let run = done.fetch_add(1, Ordering::SeqCst);
                if run == 0 {
                    panic!("the first run fails");
                }
            })
        }));
        assert!(caught.is_err());
        assert_eq!(done.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn the_threads_that_help_are_the_librarys_own() {
        let names = on_threads(4, &|| std::thread::current().name().map(str::to_owned));
        let ours = names
            .iter()
            .flatten()
            .filter(|name| name.starts_with("scionic-"))
            .count();
        assert_eq!(ours, 3, "{names:?}");
    }
}
