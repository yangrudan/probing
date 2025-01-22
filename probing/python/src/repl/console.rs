use pyo3::{
    types::{PyAnyMethods, PyDict},
    Bound, Py, PyAny, Python,
};

use crate::repl::python_repl::PythonConsole;

#[cfg(not(debug_assertions))]
use include_dir::{include_dir, Dir};

#[cfg(not(debug_assertions))]
static ASSET: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/repl/");

#[cfg(debug_assertions)]
fn get_repl_code() -> String {
    match std::fs::read_to_string("probing/python/src/repl/debug_console.py"){
        Ok(code) => code,
        Err(err) => {
            log::error!("error loading console code from filesystem: {}", err);
            String::new()
        }
    }
}

#[cfg(not(debug_assertions))]
fn get_repl_code() -> String {
    let code = ASSET.get_file("debug_console.py");
    match code {
        Some(code) => code.contents_utf8().unwrap_or_default().to_string(),
        None => {
            log::error!("error loading console code from embedded assets");
            String::new()
        }
    }
}
pub struct NativePythonConsole {
    console: Py<PyAny>,
}

impl Default for NativePythonConsole {
    #[inline(never)]
    fn default() -> Self {
        Self {
            console: Python::with_gil(|py| {
                let global = PyDict::new(py);
                let code = get_repl_code();
                if code.is_empty() {
                    log::error!("error loading console code");
                    return py.None();
                }
                let _ = py.run_bound(code.as_str(), Some(&global), Some(&global));
                let ret: Bound<'_, PyAny> = global
                    .get_item("debug_console")
                    .map_err(|err| {
                        eprintln!("error initializing console: {}", err);
                    })
                    .unwrap();
                ret.unbind()
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

#[cfg(test)]
mod test {
    use crate::repl::python_repl::PythonConsole;

    #[test]
    fn test_python_console() {
        let mut console = super::NativePythonConsole::default();
        let ret = console.try_execute("1+1".to_string());
        assert_eq!(ret, Some("2\n".to_string()));
    }
}
