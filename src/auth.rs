use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use crate::logging::Logger;

pub struct User {
    pub login: String,
    pub password: String,
    pub root_path: PathBuf,
}

pub struct AuthManager {
    users: HashMap<String, User>,
}

impl AuthManager {
    pub fn from_file(filename: &str, logger: &Logger) -> Result<Self, String> {
        let file = File::open(filename).map_err(|e| format!("Cannot open {}: {}", filename, e))?;
        let reader = BufReader::new(file);
        let mut users = HashMap::new();
        let mut line_num = 0;
        let mut valid_users = 0;
        
        for line in reader.lines() {
            line_num += 1;
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    logger.warning(&format!("Line {}: read error - {}", line_num, e));
                    continue;
                }
            };
            
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() != 3 {
                logger.warning(&format!("Line {}: invalid format (expected: login:password:/path)", line_num));
                continue;
            }
            
            let login = parts[0].trim();
            let password = parts[1].trim();
            let root_path_str = parts[2].trim();
            
            if login.is_empty() || password.is_empty() || root_path_str.is_empty() {
                logger.warning(&format!("Line {}: empty fields not allowed", line_num));
                continue;
            }
            
            let root_path = PathBuf::from(root_path_str);
            
            if !root_path.exists() {
                logger.warning(&format!("Line {}: path {} does not exist - user ignored", 
                                       line_num, root_path.display()));
                continue;
            }
            
            if !root_path.is_absolute() {
                logger.warning(&format!("Line {}: path must be absolute - user ignored", line_num));
                continue;
            }
            
            if !root_path.is_dir() {
                logger.warning(&format!("Line {}: path {} is not a directory - user ignored", 
                                       line_num, root_path.display()));
                continue;
            }
            
            let user = User {
                login: login.to_string(),
                password: password.to_string(),
                root_path,
            };
            
            users.insert(login.to_string(), user);
            valid_users += 1;
            logger.debug(&format!("User loaded: {} from {}", login, root_path_str));
        }
        
        if users.is_empty() {
            return Err("No valid users found in file".to_string());
        }
        
        logger.info(&format!("{} valid user(s) loaded from {} line(s)", valid_users, line_num));
        Ok(AuthManager { users })
    }
    
    pub fn authenticate(&self, login: &str, password: &str) -> Option<&User> {
        self.users.get(login).and_then(|user| {
            if user.password == password {
                Some(user)
            } else {
                None
            }
        })
    }
    
    pub fn count(&self) -> usize {
        self.users.len()
    }
}

