use std::collections::HashSet;
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;
use std::sync::atomic::{AtomicI32, Ordering};

use anyhow::Result;
use async_trait::async_trait;
use lazy_static::lazy_static;
use nix::libc;
use once_cell::sync::Lazy;

use probing_proto::prelude::CallFrame;

use crate::features::vm_tracer::get_python_stacks_raw;

// Pipe file descriptors for async-signal-safe communication
static PIPE_READ_FD: AtomicI32 = AtomicI32::new(-1);
static PIPE_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

/// Async-signal-safe error logging to STDERR
/// This function can be safely called from signal handlers
fn log_to_stderr(msg: &str) {
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr() as *const libc::c_void, msg.len());
    }
}

/// Initialize the pipe for async-signal-safe communication
/// Returns Ok(()) if pipe is created successfully, Err otherwise
pub fn init_pipe() -> Result<()> {
    let mut fds: [i32; 2] = [-1, -1];
    
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    
    if ret != 0 {
        let errno = unsafe { *libc::__errno_location() };
        let error_msg = format!(
            "[ERROR] stack_tracer::init_pipe: Failed to create pipe, errno={}\n",
            errno
        );
        log_to_stderr(&error_msg);
        return Err(anyhow::anyhow!("Failed to create pipe, errno={}", errno));
    }
    
    PIPE_READ_FD.store(fds[0], Ordering::SeqCst);
    PIPE_WRITE_FD.store(fds[1], Ordering::SeqCst);
    
    Ok(())
}

/// Read raw frames from the pipe
/// This function performs error checking and logs failures to STDERR
pub fn read_raw_frames_from_pipe(timeout_ms: i32) -> Result<Vec<u8>> {
    let read_fd = PIPE_READ_FD.load(Ordering::SeqCst);
    
    // Check if pipe is initialized
    if read_fd < 0 {
        let error_msg = "[ERROR] stack_tracer::read_raw_frames_from_pipe: Pipe not initialized\n";
        log_to_stderr(error_msg);
        return Err(anyhow::anyhow!("Pipe not initialized"));
    }
    
    // Poll the pipe for readability
    let mut pollfd = libc::pollfd {
        fd: read_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    
    let poll_ret = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
    
    if poll_ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        let error_msg = format!(
            "[ERROR] stack_tracer::read_raw_frames_from_pipe: poll() failed, errno={}\n",
            errno
        );
        log_to_stderr(&error_msg);
        return Err(anyhow::anyhow!("poll() failed, errno={}", errno));
    }
    
    if poll_ret == 0 {
        let error_msg = "[WARN] stack_tracer::read_raw_frames_from_pipe: poll() timeout\n";
        log_to_stderr(error_msg);
        return Err(anyhow::anyhow!("poll() timeout"));
    }
    
    // Read the frame count first (4 bytes)
    let mut frame_count_bytes = [0u8; 4];
    let read_ret = unsafe {
        libc::read(
            read_fd,
            frame_count_bytes.as_mut_ptr() as *mut libc::c_void,
            4,
        )
    };
    
    if read_ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        let error_msg = format!(
            "[ERROR] stack_tracer::read_raw_frames_from_pipe: read() failed for frame count, errno={}\n",
            errno
        );
        log_to_stderr(&error_msg);
        return Err(anyhow::anyhow!("read() failed for frame count, errno={}", errno));
    }
    
    if read_ret != 4 {
        let error_msg = format!(
            "[ERROR] stack_tracer::read_raw_frames_from_pipe: short read for frame count, expected 4 bytes, got {}\n",
            read_ret
        );
        log_to_stderr(&error_msg);
        return Err(anyhow::anyhow!("short read for frame count, expected 4 bytes, got {}", read_ret));
    }
    
    let frame_count = u32::from_le_bytes(frame_count_bytes);
    
    // Validate frame count
    if frame_count == 0 {
        let error_msg = "[WARN] stack_tracer::read_raw_frames_from_pipe: frame count is 0\n";
        log_to_stderr(error_msg);
        return Err(anyhow::anyhow!("frame count is 0"));
    }
    
    if frame_count > 10000 {
        let error_msg = format!(
            "[ERROR] stack_tracer::read_raw_frames_from_pipe: frame count {} exceeds maximum (10000)\n",
            frame_count
        );
        log_to_stderr(&error_msg);
        return Err(anyhow::anyhow!("frame count {} exceeds maximum", frame_count));
    }
    
    // Read the actual frame data
    let data_size = frame_count as usize;
    let mut buffer = vec![0u8; data_size];
    
    let read_ret = unsafe {
        libc::read(
            read_fd,
            buffer.as_mut_ptr() as *mut libc::c_void,
            data_size,
        )
    };
    
    if read_ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        let error_msg = format!(
            "[ERROR] stack_tracer::read_raw_frames_from_pipe: read() failed for frame data, errno={}\n",
            errno
        );
        log_to_stderr(&error_msg);
        return Err(anyhow::anyhow!("read() failed for frame data, errno={}", errno));
    }
    
    if read_ret as usize != data_size {
        let error_msg = format!(
            "[ERROR] stack_tracer::read_raw_frames_from_pipe: short read for frame data, expected {} bytes, got {}\n",
            data_size, read_ret
        );
        log_to_stderr(&error_msg);
        return Err(anyhow::anyhow!("short read for frame data, expected {} bytes, got {}", data_size, read_ret));
    }
    
    Ok(buffer)
}

#[async_trait]
pub trait StackTracer: Send + Sync + std::fmt::Debug {
    fn trace(&self, tid: Option<i32>) -> Result<Vec<CallFrame>>;
}

#[derive(Debug)]
pub struct SignalTracer;

impl SignalTracer {
    fn get_native_stacks() -> Option<Vec<CallFrame>> {
        let mut frames = vec![];
        backtrace::trace(|frame| {
            let ip = frame.ip();
            let symbol_address = frame.symbol_address(); // Keep as *mut c_void for formatting
            backtrace::resolve_frame(frame, |symbol| {
                let func_name = symbol
                    .name()
                    .and_then(|name| name.as_str())
                    .map(|raw_name| {
                        cpp_demangle::Symbol::new(raw_name)
                            .ok()
                            .map(|demangled| demangled.to_string())
                            .unwrap_or_else(|| raw_name.to_string())
                    })
                    .unwrap_or_else(|| format!("unknown@{symbol_address:p}"));

                let file_name = symbol
                    .filename()
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_default();

                frames.push(CallFrame::CFrame {
                    ip: format!("{ip:p}"),
                    file: file_name,
                    func: func_name,
                    lineno: symbol.lineno().unwrap_or(0) as i64,
                });
            });
            true
        });
        Some(frames)
    }

    fn send_frames(frames: Vec<CallFrame>) -> Result<()> {
        match NATIVE_CALLSTACK_SENDER_SLOT.try_lock() {
            Ok(guard) => {
                if let Some(sender) = guard.as_ref() {
                    sender.send(frames)?;
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("No sender available in channel slot"))
                }
            }
            Err(_) => Err(anyhow::anyhow!("Failed to send frames via channel")),
        }
    }

    fn merge_python_native_stacks(
        python_stacks: Vec<CallFrame>,
        native_stacks: Vec<CallFrame>,
    ) -> Vec<CallFrame> {
        let mut merged = vec![];
        let mut python_frame_index = 0;

        enum MergeType {
            Ignore,
            MergeNativeFrame,
            MergePythonFrame,
        }

        fn get_merge_strategy(frame: &CallFrame) -> MergeType {
            lazy_static! {
                static ref WHITELISTED_PREFIXES_SET: HashSet<&'static str> = {
                    const PREFIXES: &[&str] = &[
                        "time",
                        "sys",
                        "gc",
                        "os",
                        "unicode",
                        "thread",
                        "stringio",
                        "sre",
                        "PyGilState",
                        "PyThread",
                        "lock",
                    ];
                    PREFIXES.iter().cloned().collect()
                };
            }
            let symbol = match frame {
                CallFrame::CFrame { func, .. } => func,
                CallFrame::PyFrame { func, .. } => func,
            };
            let mut tokens = symbol.split(['_', '.']).filter(|s| !s.is_empty());
            match tokens.next() {
                Some("PyEval") => match tokens.next() {
                    Some("EvalFrameDefault" | "EvalFrameEx") => MergeType::MergePythonFrame,
                    _ => MergeType::Ignore,
                },
                Some(prefix) if WHITELISTED_PREFIXES_SET.contains(prefix) => {
                    MergeType::MergeNativeFrame
                }
                _ => MergeType::MergeNativeFrame,
            }
        }

        for frame in native_stacks {
            // log::debug!("Processing native frame: {:?}", frame);
            match get_merge_strategy(&frame) {
                MergeType::Ignore => {} // Do nothing
                MergeType::MergeNativeFrame => merged.push(frame),
                MergeType::MergePythonFrame => {
                    if let Some(py_frame) = python_stacks.get(python_frame_index) {
                        merged.push(py_frame.clone());
                    }
                    python_frame_index += 1; // Advance index regardless of whether a Python frame was available
                }
            }
        }
        merged
    }
}

#[async_trait]
impl StackTracer for SignalTracer {
    fn trace(&self, tid: Option<i32>) -> Result<Vec<CallFrame>> {
        log::debug!("Collecting backtrace for TID: {tid:?}");

        let pid = nix::unistd::getpid().as_raw(); // PID of the current process (thread group ID)
        let tid = tid.unwrap_or(pid); // Target thread ID, or current process's PID if tid_param is None (signals the main thread)

        let _guard = BACKTRACE_MUTEX.try_lock().map_err(|e| {
            log::error!("Failed to acquire BACKTRACE_MUTEX: {e}");
            anyhow::anyhow!("Failed to acquire backtrace lock: {}", e)
        })?;

        let (tx, rx) = mpsc::channel::<Vec<CallFrame>>();
        NATIVE_CALLSTACK_SENDER_SLOT
            .try_lock()
            .map_err(|err| {
                log::error!("Failed to lock CALLSTACK_SENDER_SLOT: {err}");
                anyhow::anyhow!("Failed to lock call stack sender slot")
            })?
            .replace(tx);

        log::debug!("Sending SIGUSR2 signal to process {pid} (thread: {tid})");

        #[cfg(target_os = "linux")]
        let ret = unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGUSR2) };

        #[cfg(target_os = "macos")]
        let ret = unsafe { libc::kill(tid, libc::SIGUSR2) };

        if ret != 0 {
            let last_error = std::io::Error::last_os_error();
            let error_msg =
                format!("Failed to send SIGUSR2 to process {pid} (thread: {tid}): {last_error}");
            log::error!("{error_msg}");
            return Err(anyhow::anyhow!(error_msg));
        }

        let native_frames = rx.recv_timeout(Duration::from_secs(2))?;
        let python_frames = rx.recv_timeout(Duration::from_secs(2))?;

        Ok(Self::merge_python_native_stacks(
            python_frames,
            native_frames,
        ))
    }
}

pub fn backtrace_signal_handler() {
    let native_stacks = SignalTracer::get_native_stacks().unwrap_or_default();
    let python_stacks = get_python_stacks_raw();
    if SignalTracer::send_frames(native_stacks).is_err() {
        // Use async-signal-safe logging instead of log::error!
        let error_msg = "[ERROR] backtrace_signal_handler: Failed to send native stacks. Receiver might timeout or get incomplete data.\n";
        log_to_stderr(error_msg);
    }
    if SignalTracer::send_frames(python_stacks).is_err() {
        // Use async-signal-safe logging instead of log::error!
        let error_msg = "[ERROR] backtrace_signal_handler: Failed to send Python stacks. Receiver might timeout or get incomplete data.\n";
        log_to_stderr(error_msg);
    }
}

/// Define a static Mutex for the backtrace function
static BACKTRACE_MUTEX: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

pub static NATIVE_CALLSTACK_SENDER_SLOT: Lazy<Mutex<Option<mpsc::Sender<Vec<CallFrame>>>>> =
    Lazy::new(|| Mutex::new(None));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_pipe_success() {
        // Initialize the pipe
        let result = init_pipe();
        assert!(result.is_ok(), "init_pipe should succeed");
        
        // Verify that the file descriptors are set
        let read_fd = PIPE_READ_FD.load(Ordering::SeqCst);
        let write_fd = PIPE_WRITE_FD.load(Ordering::SeqCst);
        
        assert!(read_fd >= 0, "Read FD should be valid");
        assert!(write_fd >= 0, "Write FD should be valid");
        
        // Clean up
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        PIPE_READ_FD.store(-1, Ordering::SeqCst);
        PIPE_WRITE_FD.store(-1, Ordering::SeqCst);
    }

    #[test]
    fn test_read_raw_frames_from_pipe_not_initialized() {
        // Ensure pipe is not initialized
        PIPE_READ_FD.store(-1, Ordering::SeqCst);
        
        // Try to read from uninitialized pipe
        let result = read_raw_frames_from_pipe(100);
        assert!(result.is_err(), "Should fail when pipe is not initialized");
        assert!(result.unwrap_err().to_string().contains("not initialized"));
    }

    #[test]
    fn test_read_raw_frames_from_pipe_timeout() {
        // Initialize the pipe
        init_pipe().expect("Failed to init pipe");
        
        // Try to read with a short timeout (pipe is empty)
        let result = read_raw_frames_from_pipe(10);
        assert!(result.is_err(), "Should timeout when no data is available");
        
        // Clean up
        let read_fd = PIPE_READ_FD.load(Ordering::SeqCst);
        let write_fd = PIPE_WRITE_FD.load(Ordering::SeqCst);
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        PIPE_READ_FD.store(-1, Ordering::SeqCst);
        PIPE_WRITE_FD.store(-1, Ordering::SeqCst);
    }

    #[test]
    fn test_log_to_stderr() {
        // This test just ensures log_to_stderr doesn't panic
        // In a real scenario, we'd capture STDERR to verify output
        log_to_stderr("Test error message\n");
    }
}
