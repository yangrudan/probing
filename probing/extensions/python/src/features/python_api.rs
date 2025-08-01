use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::extensions;
use crate::features::vm_tracer::{
    _get_python_frames, _get_python_stacks, disable_tracer, enable_tracer, initialize_globals,
};
use crate::pkg::TCPStore;
use probing_core::ENGINE;

#[pyfunction]
fn query_json(_py: Python, sql: String) -> PyResult<String> {
    let result = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { ENGINE.read().await.async_query(sql.as_str()).await })
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
    serde_json::to_string(&result)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

pub fn create_probing_module() -> PyResult<()> {
    if initialize_globals() {
        #[cfg(feature = "tracing")]
        Python::with_gil(|_| enable_tracer())?;
    }
    Python::with_gil(|py| -> PyResult<()> {
        let sys = PyModule::import(py, "sys")?;
        let modules = sys.getattr("modules")?;

        if !modules.contains("probing")? {
            let m = PyModule::new(py, "probing")?;
            modules.set_item("probing", m)?;
        }

        let m = PyModule::import(py, "probing")?;
        if m.hasattr(pyo3::intern!(py, "_C"))? {
            return Ok(());
        }
        m.setattr(pyo3::intern!(py, "_C"), 42)?;
        m.add_class::<extensions::python::ExternalTable>()?;
        m.add_class::<TCPStore>()?;
        m.add_function(wrap_pyfunction!(query_json, py)?)?;
        m.add_function(wrap_pyfunction!(enable_tracer, py)?)?;
        m.add_function(wrap_pyfunction!(disable_tracer, py)?)?;
        m.add_function(wrap_pyfunction!(_get_python_stacks, py)?)?;
        m.add_function(wrap_pyfunction!(_get_python_frames, py)?)?;
        Ok(())
    })
}
