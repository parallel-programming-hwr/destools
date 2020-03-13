use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct TimeTaker {
    start_values: HashMap<String, Instant>,
}

impl TimeTaker {
    /// Creates a new time taker
    pub fn new() -> Self {
        Self {
            start_values: HashMap::new(),
        }
    }

    /// Takes the current time for a name
    pub fn take(&mut self, name: &str) -> Instant {
        let time = Instant::now();
        self.start_values.insert(name.to_string(), time);

        time
    }

    /// Returns the elapsed time for a start time name
    pub fn since(&self, name: &str) -> Option<Duration> {
        if let Some(start) = self.start_values.get(name) {
            return Some(start.elapsed());
        }

        None
    }
}
