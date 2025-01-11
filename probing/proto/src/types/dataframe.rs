use serde::{Deserialize, Serialize};

use crate::types::array::Array;

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct DataFrame {
    pub names: Vec<String>,
    pub cols: Vec<Array>,
}

impl DataFrame {
    pub fn new(names: Vec<String>, columns: Vec<Array>) -> Self {
        DataFrame {
            names,
            cols: columns,
        }
    }

    pub fn len(&self) -> usize {
        if self.cols.is_empty() {
            return 0;
        }
        self.cols[0].len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
