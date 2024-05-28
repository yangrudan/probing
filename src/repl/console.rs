use once_cell::sync::Lazy;
use pyo3::{
    types::{PyAnyMethods, PyDict},
    Bound, Py, PyAny, Python,
};

use crate::repl::repl::PythonConsole;

pub const CODE: &str = include_str!("debug_console.py");

pub struct NativePythonConsole {
    console: Lazy<Py<PyAny>>,
}

impl Default for NativePythonConsole {
    #[inline(never)]
    fn default() -> Self {
        Self {
            console: Lazy::new(|| {
                Python::with_gil(|py| {
                    let global = PyDict::new_bound(py);
                    let _ = py.run_bound(CODE, Some(&global), Some(&global));
                    let ret: Bound<'_, PyAny> = global.get_item("debug_console").unwrap();
                    ret.unbind()
                })
            }),
        }
    }
}

impl PythonConsole for NativePythonConsole {
    fn try_execute(&mut self, cmd: String) -> Option<String> {
        Python::with_gil(|py| match self.console.call_method1(py, "push", (cmd,)) {
            Ok(obj) => {
                if obj.is_none(py) {
                    None
                } else {
                    Some(obj.to_string())
                }
            }
            Err(err) => Some(err.to_string()),
        })
    }
}
