use std::fs::{OpenOptions, File};
use std::io::Write;
use std::sync::Mutex;
use chrono::Local;

pub struct Logger {
    file: Option<Mutex<File>>,
    is_daemon: bool,
    log_path: Option<String>,
}

impl Logger {
    pub fn new(log_path: Option<&str>, is_daemon: bool) -> Self {
        let file = log_path.and_then(|path| {
            match OpenOptions::new().create(true).append(true).open(path) {
                Ok(f) => {
                    Some(Mutex::new(f))
                }
                Err(e) => {
                    eprintln!("Warning: cannot open log file {}: {}", path, e);
                    None
                }
            }
        });
        
        Logger { 
            file, 
            is_daemon,
            log_path: log_path.map(String::from),
        }
    }
    
    fn timestamp() -> String {
        Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
    }
    
    pub fn log(&self, level: &str, message: &str) {
        let timestamp = Self::timestamp();
        let log_line = format!("{} [{}] {}\n", timestamp, level, message);
        
        if let Some(mutex) = &self.file {
            match mutex.lock() {
                Ok(mut file) => {
                    let _ = file.write_all(log_line.as_bytes());
                    let _ = file.flush();
                }
                Err(e) => {
                    eprintln!("Log file lock error: {}", e);
                }
            }
        }
        
        if !self.is_daemon {
            print!("{}", log_line);
            let _ = std::io::stdout().flush();
        }
    }
    
    pub fn info(&self, message: &str) {
        self.log("INFO", message);
    }
    
    pub fn error(&self, message: &str) {
        self.log("ERROR", message);
    }
    
    pub fn warning(&self, message: &str) {
        self.log("WARNING", message);
    }
    
    pub fn debug(&self, message: &str) {
        if !self.is_daemon {
            self.log("DEBUG", message);
        }
    }
    
    pub fn access(&self, ip: &str, user: &str, method: &str, path: &str, status: u16, size: u64) {
        let message = format!("{} - {} [{}] {} {} {}", ip, user, method, path, status, size);
        self.log("ACCESS", &message);
    }
}

impl Clone for Logger {
    fn clone(&self) -> Self {
        let file = self.log_path.as_deref().and_then(|path| {
            match OpenOptions::new().create(true).append(true).open(path) {
                Ok(f) => Some(Mutex::new(f)),
                Err(e) => {
                    eprintln!("Warning: cannot open log file {}: {}", path, e);
                    None
                }
            }
        });
        
        Logger {
            file,
            is_daemon: self.is_daemon,
            log_path: self.log_path.clone(),
        }
    }
}

