use anyhow::Context;
use anyhow::Result;
use procfs::process;
use std::fmt::Display;

// const LIBC_NAME: &str = "libc.so.6";

/// A process to attach to.
#[derive(Debug)]
pub struct Process(process::Process);

impl Display for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.pid)
    }
}

impl Process {
    /// Get the current running process (for comparing libc addresses).
    pub(crate) fn current() -> Result<Self> {
        Ok(Self(
            process::Process::myself().context("failed to get PID of current process")?,
        ))
    }

    /// Get a process by its PID.
    ///
    /// # Panics
    ///
    /// This function panics if the conversion from `u32` to `i32` fails.
    pub fn get(id: u32) -> Result<Self> {
        // https://unix.stackexchange.com/a/16884 - A PID should fit in 31 bits comfortably.
        let id = i32::try_from(id).expect("PID to fit in an i32");
        log::trace!("Getting process with PID {id}");
        Ok(Self(process::Process::new(id).with_context(|| {
            format!("failed to get process by pid {id}")
        })?))
    }

    /// Search for a process by the name of its executable.
    ///
    /// This ignores errors when the executable name of certain processes cannot
    /// be read (usually because of lack of permissions).
    pub fn by_name(name: &str) -> Result<Option<Self>> {
        log::debug!("Searching for process with executable name {name}");
        for process in
            process::all_processes().context("failed to list processes to search them")?
        {
            let process = process.context("failed to read process metadata to check its name")?;
            log::trace!("Checking process {}", process.pid);
            if let Ok(exe) = process.exe() {
                if exe.ends_with(name) {
                    log::info!("Found process with PID {}", process.pid);
                    return Ok(Some(Self(process)));
                }
            } else {
                // This is common, if we don't have permissions to read certain
                // processes information.
                log::trace!("Could not read executable name of process {}", process.pid);
            }
        }
        Ok(None)
    }

    /// Search for a process by the name of its cmdline.
    ///
    /// This ignores errors when the executable name of certain processes cannot
    /// be read (usually because of lack of permissions).
    pub fn by_cmdline(pat: &str) -> Result<Option<i32>> {
        log::debug!("Searching for process with executable name {pat}");
        let ps: Vec<i32> = process::all_processes()
            .context("failed to list processes to search them")?
            .filter_map(std::result::Result::ok)
            .filter_map(|p| {
                p.cmdline().map_or(None, |cmdline| {
                    let cmdline = cmdline.join(" ");
                    if cmdline.contains(pat) {
                        Some(p.pid())
                    } else {
                        None
                    }
                })
            })
            .collect();
        match ps.len() {
            1 => Ok(Some(ps[0])),
            0 => Err(anyhow::anyhow!(
                "found no process with cmdline pattern: {}",
                pat
            )),
            _ => Err(anyhow::anyhow!(
                "found multiple processes with cmdline pattern: {}",
                pat
            )),
        }
    }

    /// Find a suitable address to inject the shellcode into.
    pub(crate) fn find_executable_space(&self) -> Result<u64> {
        log::trace!("Finding executable space in target process");
        self.0
            .maps()
            .context("failed to read process memory maps to find executable region")?
            .into_iter()
            .find(|m| m.perms.contains(process::MMPermissions::EXECUTE))
            .map(|m| m.address.0)
            .ok_or_else(|| {
                anyhow::anyhow!("could not find an executable region in the target process")
            })
    }

    /// Get the address of the libc library in the process.
    pub(crate) fn libc_address(&self) -> Result<u64> {
        // let library = std::path::PathBuf::from(LIBC_NAME);
        log::trace!("Finding libc address in process with PID {}", self.0.pid);
        self.0
            .maps()
            .context("failed to read process memory maps to find libc")?
            .into_iter()
            .find(move |m| {
                log::trace!("Checking mapping: {m:?}");
                match &m.pathname {
                    process::MMapPath::Path(path) => {
                        path.to_string_lossy().contains("/libc.")
                            || path.to_string_lossy().contains("/libc-")
                    } //path.ends_with(&library),
                    _ => false,
                }
            })
            .map(|m| m.address.0)
            .ok_or_else(|| anyhow::anyhow!("could not find libc in the target process"))
    }
    /// Get the address of the libc library in the process.
    pub(crate) fn libdl_address(&self) -> Result<u64> {
        // let library = std::path::PathBuf::from(LIBC_NAME);
        log::trace!("Finding libc address in process with PID {}", self.0.pid);
        self.0
            .maps()
            .context("failed to read process memory maps to find libc")?
            .into_iter()
            .find(move |m| {
                log::trace!("Checking mapping: {m:?}");
                match &m.pathname {
                    process::MMapPath::Path(path) => {
                        path.to_string_lossy().contains("/libdl.")
                            || path.to_string_lossy().contains("/libdl-")
                    } //path.ends_with(&library),
                    _ => false,
                }
            })
            .map(|m| m.address.0)
            .ok_or_else(|| anyhow::anyhow!("could not find libc in the target process"))
    }
    /// Get the TIDs of each of the threads in the process.
    pub(crate) fn thread_ids(&self) -> Result<Vec<i32>> {
        log::trace!("Getting thread IDs of process with PID {}", self.0.pid);
        self.0
            .tasks()
            .context("failed to read process thread IDs")?
            .map(|t| Ok(t.context("failed to read process thread IDs")?.tid))
            .collect()
    }

    /// Get the process ID.
    pub(crate) const fn pid(&self) -> i32 {
        self.0.pid
    }
}

impl From<&Process> for pete::Pid {
    fn from(proc: &Process) -> Self {
        Self::from_raw(proc.0.pid)
    }
}

impl From<&Process> for nix::unistd::Pid {
    fn from(proc: &Process) -> Self {
        Self::from_raw(proc.0.pid)
    }
}
