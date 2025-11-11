use std::collections::HashSet;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Once;

use anyhow::Result;
use async_trait::async_trait;
use lazy_static::lazy_static;
use nix::libc;
use once_cell::sync::Lazy;

use probing_proto::prelude::CallFrame;

use super::super::extensions::python::get_python_stacks;

#[async_trait]
pub trait StackTracer: Send + Sync + std::fmt::Debug {
    fn trace(&self, tid: Option<i32>) -> Result<Vec<CallFrame>>;
}

#[derive(Debug)]
pub struct SignalTracer;

impl SignalTracer {
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

        // Initialize pipe if not already done
        if PIPE_READ_FD.load(Ordering::SeqCst) < 0 {
            init_pipe()?;
        }

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

        // Read native frames from pipe (timeout in milliseconds)
        let native_raw_frames = read_raw_frames_from_pipe(2000)?;
        let native_frames = resolve_frames(native_raw_frames);
        
        // Get Python frames directly
        let python_frames = get_python_stacks(tid).unwrap();

        Ok(Self::merge_python_native_stacks(
            python_frames,
            native_frames,
        ))
    }
}

pub fn backtrace_signal_handler() {
    // Signal-safe backtrace collection
    let write_fd = PIPE_WRITE_FD.load(Ordering::SeqCst);
    if write_fd < 0 {
        unsafe {
            let msg = b"Backtrace signal handler: pipe not initialized\n";
            libc::write(libc::STDERR_FILENO, msg.as_ptr() as *const _, msg.len());
        }
        return; // Pipe not initialized, cannot send data
    }
    
    // Pre-allocate buffer for frame addresses
    let mut buffer: [*mut libc::c_void; MAX_FRAMES] = [std::ptr::null_mut(); MAX_FRAMES];
    let mut count: usize = 0;
    
    // Use trace_unsynchronized for async-signal-safe backtrace
    unsafe {
        backtrace::trace_unsynchronized(|frame| {
            if count < MAX_FRAMES {
                buffer[count] = frame.ip();
                count += 1;
                true
            } else {
                false
            }
        });
    }
    
    if count > MAX_FRAMES {
        unsafe {
            let msg = format!(
                "Backtrace signal handler: Frame count exceeds limit ({} > {})\n",
                count, MAX_FRAMES
            );
            libc::write(libc::STDERR_FILENO, msg.as_ptr() as *const _, msg.len());
        }
        return; // Exceeded max frames, avoid partial data
    }
    
    // Write count as u32 (4 bytes)
    let count_u32 = count as u32;
    let count_bytes = count_u32.to_ne_bytes();
    
    // Write count with error checking
    let written = unsafe {
        libc::write(write_fd, count_bytes.as_ptr() as *const libc::c_void, 4)
    };
    
    if written != 4 {
        unsafe {
            let msg = format!(
                "Backtrace signal handler: Failed to write frame count (errno={})\n",
                *libc::__errno_location()
            );
            libc::write(libc::STDERR_FILENO, msg.as_ptr() as *const _, msg.len());
        }
        return; // Failed to write count, abort
    }
    
    // Write frame addresses (using usize for consistency)
    let addr_size = std::mem::size_of::<usize>();
    for i in 0..count {
        let addr = buffer[i] as usize;
        let addr_bytes = addr.to_ne_bytes();
        
        let written = unsafe {
            libc::write(write_fd, addr_bytes.as_ptr() as *const libc::c_void, addr_size)
        };
        
        if written != addr_size as isize {
            unsafe {
                let msg = format!(
                    "Backtrace signal handler: Failed to write frame {} (errno={})\n",
                    i, *libc::__errno_location()
                );
                libc::write(libc::STDERR_FILENO, msg.as_ptr() as *const _, msg.len());
            }
            return; // Failed to write frame, abort to prevent partial data
        }
    }
}

/// Define a static Mutex for the backtrace function
static BACKTRACE_MUTEX: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

// Pipe file descriptors for async-signal-safe communication
static PIPE_READ_FD: AtomicI32 = AtomicI32::new(-1);
static PIPE_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

// Ensure pipe is initialized only once
static PIPE_INIT: Once = Once::new();

// Maximum number of frames to capture
const MAX_FRAMES: usize = 512;

/// Initialize the pipe for signal-safe communication
fn init_pipe() -> Result<()> {
    let mut result = Ok(());
    
    PIPE_INIT.call_once(|| {
        let mut fds: [libc::c_int; 2] = [0, 0];
        // Use O_CLOEXEC but not O_NONBLOCK to ensure writes don't fail in signal handler
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        
        if ret != 0 {
            result = Err(anyhow::anyhow!("Failed to create pipe: {}", std::io::Error::last_os_error()));
            return;
        }
        
        PIPE_READ_FD.store(fds[0], Ordering::SeqCst);
        PIPE_WRITE_FD.store(fds[1], Ordering::SeqCst);
    });
    
    // Check if initialization succeeded
    if PIPE_READ_FD.load(Ordering::SeqCst) < 0 {
        return Err(anyhow::anyhow!("Pipe initialization failed"));
    }
    
    result
}

/// Read raw frame addresses from the pipe
fn read_raw_frames_from_pipe(timeout_ms: i32) -> Result<Vec<*mut libc::c_void>> {
    let read_fd = PIPE_READ_FD.load(Ordering::SeqCst);
    if read_fd < 0 {
        return Err(anyhow::anyhow!("Pipe not initialized"));
    }
    
    // Use libc::poll to wait for data with timeout
    let mut pollfd = libc::pollfd {
        fd: read_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    
    let poll_ret = unsafe { libc::poll(&mut pollfd as *mut libc::pollfd, 1, timeout_ms) };
    
    if poll_ret < 0 {
        return Err(anyhow::anyhow!("Poll failed: {}", std::io::Error::last_os_error()));
    }
    
    if poll_ret == 0 {
        return Err(anyhow::anyhow!("Timeout waiting for backtrace data"));
    }
    
    // First read the count (u32 = 4 bytes)
    let mut count_buf = [0u8; 4];
    let count_bytes_read = unsafe {
        libc::read(read_fd, count_buf.as_mut_ptr() as *mut libc::c_void, 4)
    };
    
    if count_bytes_read < 0 {
        return Err(anyhow::anyhow!("Failed to read frame count: {}", std::io::Error::last_os_error()));
    }
    
    if count_bytes_read != 4 {
        return Err(anyhow::anyhow!("Incomplete frame count read"));
    }
    
    let count = u32::from_ne_bytes(count_buf) as usize;
    
    if count > MAX_FRAMES {
        return Err(anyhow::anyhow!("Frame count exceeds maximum: {}", count));
    }
    
    // Read frame addresses (count * sizeof(usize))
    // Use size_of::<usize> consistently as addresses are serialized as usize
    let addr_size = std::mem::size_of::<usize>();
    let total_bytes = count * addr_size;
    let mut buffer = vec![0u8; total_bytes];
    
    let mut bytes_read = 0;
    while bytes_read < total_bytes {
        let n = unsafe {
            libc::read(
                read_fd,
                buffer[bytes_read..].as_mut_ptr() as *mut libc::c_void,
                total_bytes - bytes_read,
            )
        };
        
        if n < 0 {
            return Err(anyhow::anyhow!("Failed to read frame data: {}", std::io::Error::last_os_error()));
        }
        
        if n == 0 {
            return Err(anyhow::anyhow!("Unexpected EOF while reading frames"));
        }
        
        bytes_read += n as usize;
    }
    
    // Convert bytes to frame addresses
    let mut frames = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * addr_size;
        let mut addr_bytes = [0u8; std::mem::size_of::<usize>()];
        addr_bytes.copy_from_slice(&buffer[offset..offset + addr_size]);
        let addr = usize::from_ne_bytes(addr_bytes);
        frames.push(addr as *mut libc::c_void);
    }
    
    Ok(frames)
}

/// Resolve raw frame addresses to CallFrame structures
fn resolve_frames(raw_frames: Vec<*mut libc::c_void>) -> Vec<CallFrame> {
    let mut frames = vec![];
    
    for frame_ptr in raw_frames {
        let ip = frame_ptr;
        let symbol_address = frame_ptr;
        
        backtrace::resolve(ip, |symbol| {
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
    }
    
    frames
}

