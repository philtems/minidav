use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::thread;
use std::sync::Arc;
use crate::logging::Logger;

struct AttemptInfo {
    count: u32,
    first_attempt: u64,
    blocked_until: Option<u64>,
}

pub struct BruteForceProtector {
    attempts: Mutex<HashMap<String, AttemptInfo>>,
    max_attempts: u32,
    block_time: u64,
}

impl BruteForceProtector {
    pub fn new(max_attempts: u32, block_time: u64) -> Arc<Self> {
        let protector = Arc::new(BruteForceProtector {
            attempts: Mutex::new(HashMap::new()),
            max_attempts,
            block_time,
        });
        
        let cleanup_protector = protector.clone();
        thread::spawn(move || {
            cleanup_protector.cleanup_loop();
        });
        
        protector
    }
    
    pub fn get_block_time(&self) -> u64 {
        self.block_time
    }
    
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
    }
    
    pub fn is_blocked(&self, ip: &str, logger: &Logger) -> bool {
        let mut attempts = self.attempts.lock().unwrap();
        let now = Self::now();
        
        if let Some(info) = attempts.get_mut(ip) {
            if let Some(blocked_until) = info.blocked_until {
                if now < blocked_until {
                    logger.debug(&format!("IP {} blocked until {}", ip, blocked_until));
                    return true;
                } else {
                    info.count = 0;
                    info.first_attempt = now;
                    info.blocked_until = None;
                }
            }
            
            if now - info.first_attempt > 3600 {
                info.count = 0;
                info.first_attempt = now;
            }
        }
        
        false
    }
    
    pub fn record_failure(&self, ip: &str, logger: &Logger) -> bool {
        let mut attempts = self.attempts.lock().unwrap();
        let now = Self::now();
        
        let info = attempts.entry(ip.to_string()).or_insert(AttemptInfo {
            count: 0,
            first_attempt: now,
            blocked_until: None,
        });
        
        if now - info.first_attempt > 3600 {
            info.count = 0;
            info.first_attempt = now;
        }
        
        info.count += 1;
        
        logger.debug(&format!("IP {}: failed attempt {}/{}", ip, info.count, self.max_attempts));
        
        if info.count >= self.max_attempts {
            let blocked_until = now + self.block_time;
            info.blocked_until = Some(blocked_until);
            logger.warning(&format!("IP {} blocked for {} seconds after {} attempts", 
                                   ip, self.block_time, info.count));
            true
        } else {
            false
        }
    }
    
    pub fn record_success(&self, ip: &str) {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.remove(ip);
    }
    
    fn cleanup_loop(&self) {
        loop {
            thread::sleep(Duration::from_secs(60));
            
            let mut attempts = self.attempts.lock().unwrap();
            let now = Self::now();
            
            attempts.retain(|_, info| {
                if let Some(blocked_until) = info.blocked_until {
                    now < blocked_until || now - blocked_until < 3600
                } else {
                    now - info.first_attempt < 3600
                }
            });
        }
    }
}

