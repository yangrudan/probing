use anyhow::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::series::SeriesError;
use super::series::SeriesIterator;
use super::{series::SeriesConfig, value::DataType, Series, Value};

#[derive(Debug, Error)]
pub enum TimeSeriesError {
    #[error("column count mismatch")]
    ColumnCountMismatch { expected: usize, got: usize },
    #[error("column type mismatch")]
    ColumnTypeMismatch { expected: DataType, got: DataType },
    #[error("invalid timestamp type")]
    InvalidTimestampType,
    #[error("unkown error")]
    UnknownError(String),
}

impl From<SeriesError> for TimeSeriesError {
    fn from(err: SeriesError) -> Self {
        match err {
            SeriesError::TypeMismatch { expected, got } => {
                TimeSeriesError::ColumnTypeMismatch { expected, got }
            }
            _ => TimeSeriesError::UnknownError(err.to_string()),
        }
    }
}

/// A time series is multiple series shares the same timestamp.
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct TimeSeries {
    pub names: Vec<String>,
    pub timestamp: Series,
    pub cols: Vec<Series>,
}

impl TimeSeries {
    pub fn builder() -> TimeSeriesConfig {
        Default::default()
    }

    pub fn append(&mut self, timestamp: Value, values: Vec<Value>) -> Result<(), TimeSeriesError> {
        if self.cols.len() != values.len() {
            return Err(TimeSeriesError::ColumnCountMismatch {
                expected: self.cols.len(),
                got: values.len(),
            });
        }
        self.timestamp.append_value(timestamp)?;
        for i in 0..self.cols.len() {
            self.cols[i].append_value(values[i].clone())?;
        }
        Ok(())
    }

    pub fn iter(&self) -> TimeSeriesIter {
        TimeSeriesIter {
            timestamp: self.timestamp.iter(),
            cols: self.cols.iter().map(|s| s.iter()).collect(),
        }
    }
}

pub struct TimeSeriesConfig {
    series_config: SeriesConfig,
    names: Vec<String>,
}

impl Default for TimeSeriesConfig {
    fn default() -> Self {
        Self {
            series_config: Default::default(),
            names: Default::default(),
        }
    }
}

impl TimeSeriesConfig {
    pub fn with_dtype(mut self, dtype: DataType) -> Self {
        self.series_config = self.series_config.with_dtype(dtype);
        self
    }
    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.series_config = self.series_config.with_chunk_size(chunk_size);
        self
    }
    pub fn with_compression_level(mut self, compression_level: usize) -> Self {
        self.series_config = self.series_config.with_compression_level(compression_level);
        self
    }
    pub fn with_compression_threshold(mut self, compression_threshold: usize) -> Self {
        self.series_config = self
            .series_config
            .with_compression_threshold(compression_threshold);
        self
    }
    pub fn with_discard_threshold(mut self, discard_threshold: usize) -> Self {
        self.series_config = self.series_config.with_discard_threshold(discard_threshold);
        self
    }
    pub fn with_column(mut self, names: Vec<String>) -> Self {
        self.names = names;
        self
    }
    pub fn build(self) -> TimeSeries {
        let cols = self
            .names
            .iter()
            .map(|_| self.series_config.clone().build())
            .collect::<Vec<_>>();
        TimeSeries {
            names: self.names,
            timestamp: self.series_config.clone().build(),
            cols: cols,
        }
    }
}

pub struct TimeSeriesIter<'a> {
    timestamp: SeriesIterator<'a>,
    cols: Vec<SeriesIterator<'a>>,
}

impl Iterator for TimeSeriesIter<'_> {
    type Item = (Value, Vec<Value>);

    fn next(&mut self) -> Option<Self::Item> {
        let timestamp = self.timestamp.next()?;
        let cols = self
            .cols
            .iter_mut()
            .map(|s| s.next())
            .collect::<Option<Vec<_>>>()?;
        Some((timestamp, cols))
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_timeseries_create() {
        let _ = super::TimeSeries::builder()
            .with_dtype(super::DataType::Int64)
            .with_chunk_size(10)
            .with_compression_level(1)
            .with_compression_threshold(10)
            .with_discard_threshold(10)
            .with_column(vec!["a".to_string(), "b".to_string()])
            .build();
    }

    #[test]
    fn test_timeseries_append() {
        let mut ts = super::TimeSeries::builder()
            .with_dtype(super::DataType::Int64)
            .with_chunk_size(10)
            .with_compression_level(1)
            .with_compression_threshold(10)
            .with_discard_threshold(10)
            .with_column(vec!["a".to_string(), "b".to_string()])
            .build();
        let _ = ts.append(
            super::Value::Int64(1),
            vec![super::Value::Int64(1), super::Value::Int64(2)],
        );
    }
    #[test]
    fn test_timeseries_iter() {
        let mut ts = super::TimeSeries::builder()
            .with_dtype(super::DataType::Int64)
            .with_chunk_size(10)
            .with_compression_level(1)
            .with_compression_threshold(10)
            .with_discard_threshold(10)
            .with_column(vec!["a".to_string(), "b".to_string()])
            .build();

        // Append some test data
        ts.append(
            super::Value::Int64(1),
            vec![super::Value::Int64(10), super::Value::Int64(20)],
        )
        .unwrap();
        ts.append(
            super::Value::Int64(2),
            vec![super::Value::Int64(30), super::Value::Int64(40)],
        )
        .unwrap();

        // Test iteration
        let mut iter = ts.iter();

        let (t1, v1) = iter.next().unwrap();
        assert_eq!(t1, super::Value::Int64(1));
        assert_eq!(v1, vec![super::Value::Int64(10), super::Value::Int64(20)]);

        let (t2, v2) = iter.next().unwrap();
        assert_eq!(t2, super::Value::Int64(2));
        assert_eq!(v2, vec![super::Value::Int64(30), super::Value::Int64(40)]);

        assert!(iter.next().is_none());
    }
}
