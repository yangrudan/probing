pub fn register_signal_handler<F>(sig: std::ffi::c_int, handler: F)
where
    F: Fn() + Sync + Send + 'static,
{
    unsafe {
        match signal_hook_registry::register_unchecked(sig, move |_: &_| handler()) {
            Ok(_) => {
                log::debug!("Registered signal handler for signal {sig}");
            }
            Err(e) => log::error!("Failed to register signal handler: {e}"),
        }
    };
}

#[ctor]
fn setup() {
    register_signal_handler(
        nix::libc::SIGUSR2,
        crate::features::stack_tracer::backtrace_signal_handler,
    );
    register_signal_handler(
        nix::libc::SIGUSR1,
        crate::features::stack_tracer::backtrace_signal_handler_v2,
    );
    init_signal_handler();
}

use ctor::ctor;
use lazy_static::lazy_static;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use libc;

// AtomicBool to signal termination
lazy_static! {
    static ref TERM_FLAG: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
}

fn init_signal_handler() {
    // Spawn a thread to listen for termination signals
    thread::spawn(|| {
        signal_listener();
    });
    eprintln!("Signal handler initialized.");
}

fn signal_listener() {
    // register signal handlers for SIGTERM, SIGINT and SIGABRT
    let signals = [
        signal_hook::consts::SIGTERM, // kill 
        signal_hook::consts::SIGINT,  // Ctrl+C
        signal_hook::consts::SIGABRT, // abort
    ];

    // setting up signal handlers
    let registrations: Vec<_> = signals
        .iter()
        .map(|&sig| {
            signal_hook::flag::register(sig, Arc::clone(&TERM_FLAG))
                .expect("Failed to register signal")
        })
        .collect();

    // wait for termination signal
    while !TERM_FLAG.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
    }
    
    let pid = nix::unistd::getpid().as_raw(); // PID of the current process (thread group ID)
    let tid = pid;
    println!("signal listening Pid: {}", pid);
    let ret = unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGUSR1) };
    let tid = thread::current().id();
    println!("listening 线程ID (TID): {:?}", tid);
    println!("Received termination signal, saving stack trace...");


    // ensure the signal handler is unregistered
    thread::sleep(Duration::from_secs(2));
    eprintln!("Cleaning up signal handlers...");
    std::process::exit(1);
}
