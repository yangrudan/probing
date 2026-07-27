use anyhow::Result;
use async_trait::async_trait;
use probing_proto::prelude::CallFrame;

use super::super::extensions::python::get_python_stacks;

#[async_trait]
pub trait StackTracer: Send + Sync + std::fmt::Debug {
    fn trace(&self, tid: Option<i32>) -> Result<Vec<CallFrame>>;
}

#[derive(Debug)]
pub struct PythonStackTracer;

impl PythonStackTracer {
    fn trace_with<F>(&self, tid: Option<i32>, get_stacks: F) -> Result<Vec<CallFrame>>
    where
        F: FnOnce(py_spy::Pid) -> Result<Vec<CallFrame>>,
    {
        let pid = nix::unistd::getpid().as_raw();
        get_stacks(tid.unwrap_or(pid))
    }
}

#[async_trait]
impl StackTracer for PythonStackTracer {
    fn trace(&self, tid: Option<i32>) -> Result<Vec<CallFrame>> {
        log::debug!("Collecting Python stack for TID: {tid:?}");
        self.trace_with(tid, get_python_stacks)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use anyhow::anyhow;
    use probing_proto::prelude::CallFrame;

    use super::PythonStackTracer;

    #[test]
    fn returns_python_frames_for_requested_tid() {
        let tracer = PythonStackTracer;
        let expected_tid = 1234;
        let frames = tracer
            .trace_with(Some(expected_tid), |tid| {
                assert_eq!(tid, expected_tid);
                Ok(vec![CallFrame::PyFrame {
                    file: "worker.py".to_string(),
                    func: "run".to_string(),
                    lineno: 42,
                    locals: HashMap::new(),
                }])
            })
            .unwrap();

        assert_eq!(frames.len(), 1);
        assert!(matches!(frames[0], CallFrame::PyFrame { .. }));
    }

    #[test]
    fn propagates_python_stack_errors() {
        let tracer = PythonStackTracer;
        let error = tracer
            .trace_with(Some(1234), |_| {
                Err(anyhow!("unable to inspect Python process"))
            })
            .unwrap_err();

        assert_eq!(error.to_string(), "unable to inspect Python process");
    }
}
