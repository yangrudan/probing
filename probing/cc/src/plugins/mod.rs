use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::Result;
use once_cell::sync::Lazy;
use thiserror::Error;

use probing_engine::core::{
    ArrayRef, CustomSchema, DataType, Field, Float32Array, Float64Array, Int32Array, Int64Array,
    RecordBatch, Schema, SchemaPlugin, SchemaRef, StringArray,
};

use probing_proto::types::{self, TimeSeries, Value};

#[derive(Error, Debug)]
pub enum WorkerError {
    #[error("Worker already running")]
    AlreadyRunning,
    #[error("Failed to start worker: {0}")]
    StartError(String),
    #[error("Failed to stop worker: {0}")]
    StopError(String),
    #[error("Taskstats error: {0}")]
    TaskStatsError(#[from] linux_taskstats::Error),
}

pub struct WorkerConfig {
    pub interval: Duration,
    pub iterations: Option<i64>,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            iterations: None,
        }
    }
}

pub struct TaskStatsWorker {
    running: Arc<AtomicBool>,
    time_series: Arc<Mutex<TimeSeries>>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl TaskStatsWorker {
    pub fn instance() -> &'static Self {
        static INSTANCE: Lazy<TaskStatsWorker> = Lazy::new(|| TaskStatsWorker {
            running: Arc::new(AtomicBool::new(false)),
            time_series: Arc::new(Mutex::new(
                TimeSeries::builder()
                    .with_columns(vec!["cpu_utime".to_string(), "cpu_stime".to_string()])
                    .build(),
            )),
            handle: Mutex::new(None),
        });
        &INSTANCE
    }

    pub fn start(&self, config: WorkerConfig) -> Result<(), WorkerError> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(WorkerError::AlreadyRunning);
        }

        let running = self.running.clone();
        let time_series = self.time_series.clone();

        let handle = thread::spawn(move || {
            let task = match procfs::process::Process::myself() {
                Ok(p) => p,
                Err(e) => {
                    log::error!("Failed to get process: {}", e);
                    return;
                }
            };

            let mut iterations = config.iterations;
            while running.load(Ordering::SeqCst) {
                if let Some(iter) = iterations.as_mut() {
                    if *iter <= 0 {
                        break;
                    }
                    *iter -= 1;
                }

                if let Ok(stat) = task.stat() {
                    let t = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_micros() as i64;
                    let cpu_utime: Value = (stat.utime as i64).into();
                    let cpu_stime: Value = (stat.stime as i64).into();
                    match time_series
                        .lock()
                        .unwrap()
                        .append(t.into(), vec![cpu_utime, cpu_stime])
                    {
                        Ok(_) => {}
                        Err(e) => log::error!("Failed to append to time series: {}", e),
                    };
                }
                thread::sleep(config.interval);
            }
        });

        *self.handle.lock().unwrap() = Some(handle);
        Ok(())
    }

    pub fn stop(&self) -> Result<(), WorkerError> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return Ok(());
        }

        if let Some(handle) = self.handle.lock().unwrap().take() {
            handle
                .join()
                .map_err(|_| WorkerError::StopError("Thread join failed".into()))?;
        }

        Ok(())
    }

    pub fn get_stats(&self) -> Result<TimeSeries, WorkerError> {
        Ok(self.time_series.lock().unwrap().clone())
    }
}

#[derive(Default, Debug)]
pub struct TaskStatsSchema {}

impl CustomSchema for TaskStatsSchema {
    fn name() -> &'static str {
        "process"
    }

    fn list() -> Vec<String> {
        vec!["cpu".to_string(), "memory".to_string(), "io".to_string()]
    }

    fn make_lazy(expr: &str) -> Arc<probing_engine::core::LazyTableSource<Self>>
    where
        Self: Sized,
    {
        match expr {
            "cpu" => Arc::new(probing_engine::core::LazyTableSource::<Self> {
                name: expr.to_string(),
                schema: Some(SchemaRef::new(Schema::new(vec![
                    Field::new("timestamp", DataType::Int64, true),
                    Field::new("cpu_utime", DataType::Int64, false),
                    Field::new("cpu_stime", DataType::Int64, false),
                ]))),
                data: Default::default(),
            }),
            _ => Arc::new(probing_engine::core::LazyTableSource::<Self> {
                name: expr.to_string(),
                schema: None,
                data: Default::default(),
            }),
        }
    }

    fn data(expr: &str) -> Vec<RecordBatch> {
        match expr {
            "cpu" => {
                let time_series = TaskStatsWorker::instance().get_stats().unwrap();
                let names = time_series.names.clone();
                let batches = time_series_to_recordbatch(names, &time_series);

                if let Ok(batches) = batches {
                    batches
                } else {
                    log::error!("error convert time series to table: {:?}", batches.err());
                    vec![]
                }
            }
            _ => vec![],
        }
    }
}

pub type TaskStatsPlugin = SchemaPlugin<TaskStatsSchema>;

pub fn time_series_to_recordbatch(names: Vec<String>, ts: &TimeSeries) -> Result<Vec<RecordBatch>> {
    let mut fields: Vec<Field> = vec![];
    let mut columns: Vec<ArrayRef> = vec![];

    fields.push(Field::new("timestamp", DataType::Int64, true));
    names.iter().zip(ts.cols.iter()).for_each(|(name, col)| {
        let data_type = match col.dtype() {
            types::DataType::Int64 => DataType::Int64,
            types::DataType::Float64 => DataType::Float64,
            types::DataType::Int32 => DataType::Int32,
            types::DataType::Float32 => DataType::Float32,
            _ => DataType::Utf8,
        };
        fields.push(Field::new(name, data_type, false));
    });

    let length = ts.len();

    let timeseries = ts
        .timestamp
        .iter()
        .take(length)
        .map(|x| match x {
            Value::Int64(x) => x,
            _ => 0,
        })
        .collect::<Vec<_>>();
    columns.push(Arc::new(Int64Array::from(timeseries)));

    for col in ts.cols.iter() {
        let col = match col.dtype() {
            types::DataType::Int64 => Arc::new(Int64Array::from(
                col.iter()
                    .take(length)
                    .map(|x| match x {
                        Value::Int64(x) => x,
                        _ => 0,
                    })
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
            types::DataType::Float64 => Arc::new(Float64Array::from(
                col.iter()
                    .take(length)
                    .map(|x| match x {
                        Value::Float64(x) => x,
                        _ => 0.0,
                    })
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
            types::DataType::Int32 => Arc::new(Int32Array::from(
                col.iter()
                    .take(length)
                    .map(|x| match x {
                        Value::Int32(x) => x,
                        _ => 0,
                    })
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
            types::DataType::Float32 => Arc::new(Float32Array::from(
                col.iter()
                    .take(length)
                    .map(|x| match x {
                        Value::Float32(x) => x,
                        _ => 0.0,
                    })
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
            types::DataType::Text => Arc::new(StringArray::from(
                col.iter()
                    .take(length)
                    .map(|x| match x {
                        Value::Text(x) => x,
                        _ => x.to_string(),
                    })
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
            _ => Arc::new(StringArray::from(
                col.iter()
                    .take(length)
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        };

        columns.push(col);
    }

    Ok(vec![RecordBatch::try_new(
        SchemaRef::new(Schema::new(fields)),
        columns,
    )?])
}

#[cfg(test)]
mod test {
    use super::{TaskStatsWorker, WorkerConfig};

    #[test]
    fn test_task_stats_worker() {
        TaskStatsWorker::instance()
            .start(WorkerConfig {
                interval: std::time::Duration::from_millis(1),
                iterations: Some(1000),
            })
            .unwrap();

        std::thread::sleep(std::time::Duration::from_secs(2));
        let length = TaskStatsWorker::instance().get_stats().unwrap().len();

        assert_eq!(length, 1000);
    }
}
