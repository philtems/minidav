use getopts::Options;
use std::env;
use std::process::{self, Command};
use std::fs::OpenOptions;

mod auth;
mod server;
mod logging;
mod webdav;
mod brute_force;
mod hash;

use auth::AuthManager;
use logging::Logger;
use server::DavServer;
use brute_force::BruteForceProtector;
use webdav::LockManager;

const SECRET_DAEMON_FLAG: &str = "--daemonize";
const VERSION: &str = "1.4.0";
const YEAR: &str = "2026";
const AUTHOR: &str = "Philippe TEMESI";
const WEBSITE: &str = "https://www.tems.be";

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let is_daemonized = args.contains(&SECRET_DAEMON_FLAG.to_string());
    
    let mut logger = if is_daemonized { Logger::new(None, true) } else { Logger::new(None, false) };
    
    let matches = match parse_arguments(&args) {
        Ok(m) => m,
        Err(e) => {
            logger.error(&format!("Argument parsing error: {}", e));
            print_usage(&program);
            process::exit(1);
        }
    };

    if matches.opt_present("hash-password") {
        if let Some(pwd) = matches.opt_str("hash-password") {
            println!("{}", hash::hash_password(&pwd));
            process::exit(0);
        }
    }
    if matches.opt_present("h") { print_usage(&program); process::exit(0); }
    if matches.opt_present("v") { print_version(); process::exit(0); }
    if matches.opt_present("d") {
        if is_daemonized { process::exit(1); }
        start_daemon_mode(&args, &program);
        return;
    }

    let listen_addr = matches.opt_str("i").unwrap_or_else(|| "0.0.0.0".to_string());
    let port = matches.opt_str("p").unwrap_or_else(|| "8888".to_string()).parse::<u16>().unwrap_or(8888);
    
    let auth_file = matches.opt_str("auth-file").unwrap_or_else(|| {
        logger.error("Authentication file (--auth-file) is required");
        print_usage(&program);
        process::exit(1);
    });
    
    let log_file = matches.opt_str("l");
    let max_attempts = matches.opt_str("max-attempts").unwrap_or_else(|| "5".to_string()).parse::<u32>().unwrap_or(5);
    let block_time = matches.opt_str("block-time").unwrap_or_else(|| "300".to_string()).parse::<u64>().unwrap_or(300);
    let write_cache_mb = matches.opt_str("write-cache").unwrap_or_else(|| "0".to_string()).parse::<usize>().unwrap_or(0);
    let max_read_rate = matches.opt_str("max-read-rate").and_then(|s| s.parse::<u64>().ok());
    let max_write_rate = matches.opt_str("max-write-rate").and_then(|s| s.parse::<u64>().ok());

    logger = Logger::new(log_file.as_deref(), is_daemonized);
    logger.info(&format!("Starting WebDAV server v{} on {}:{}", VERSION, listen_addr, port));
    logger.info(&format!("Brute-force protection: {} max attempts, {} seconds block time", max_attempts, block_time));
    if write_cache_mb > 0 {
        logger.info(&format!("Write cache enabled: {} MB", write_cache_mb));
    } else {
        logger.info("Write cache disabled: streaming mode");
    }
    if let Some(rate) = max_read_rate { logger.info(&format!("Max Read Rate: {} Kb/s", rate)); }
    if let Some(rate) = max_write_rate { logger.info(&format!("Max Write Rate: {} Kb/s", rate)); }

    let auth_manager = match AuthManager::from_file(&auth_file, &logger) {
        Ok(am) => am,
        Err(e) => { 
            logger.error(&format!("Error loading auth file: {}", e)); 
            process::exit(1); 
        }
    };
    
    logger.info(&format!("{} user(s) loaded", auth_manager.count()));
    
    let protector = BruteForceProtector::new(max_attempts, block_time);
    let lock_manager = LockManager::new(logger.clone());

    match DavServer::new(
        &listen_addr, port,
        auth_manager, protector, lock_manager, logger.clone(),
        write_cache_mb, max_read_rate, max_write_rate
    ) {
        Ok(s) => s.run(),
        Err(e) => { 
            logger.error(&format!("Server creation error: {}", e)); 
            process::exit(1); 
        }
    }
}

fn parse_arguments(args: &[String]) -> Result<getopts::Matches, getopts::Fail> {
    let mut opts = Options::new();
    
    opts.optopt("i", "ip", "Listen address (default: 0.0.0.0)", "ADDRESS");
    opts.optopt("p", "port", "Listen port (default: 8888)", "PORT");
    opts.optopt("", "auth-file", "Authentication file (required)", "FILE");
    opts.optopt("l", "log", "Log file", "FILE");
    opts.optopt("", "max-attempts", "Max attempts before blocking (default: 5)", "NUMBER");
    opts.optopt("", "block-time", "Block time in seconds (default: 300)", "SECONDS");
    opts.optopt("", "hash-password", "Hash a password and exit", "PASSWORD");
    opts.optopt("", "write-cache", "Write cache size in MB (default: 0, disabled)", "MB");
    opts.optopt("", "max-read-rate", "Max read speed in Kb/s (default: unlimited)", "KB");
    opts.optopt("", "max-write-rate", "Max write speed in Kb/s (default: unlimited)", "KB");
    opts.optflag("d", "daemon", "Run in daemon mode");
    opts.optflag("v", "version", "Show version information");
    opts.optflag("h", "help", "Show this help");
    
    opts.optflag("", "daemonize", "Internal mode - do not use");
    
    opts.parse(&args[1..])
}

fn print_usage(program: &str) {
    println!("{} version {} ({})", program, VERSION, YEAR);
    println!("Author: {} - {}", AUTHOR, WEBSITE);
    println!();
    let brief = format!("Usage: {} [options]\n\n\
                         Minimal WebDAV server with Locking, Range support and Rate Limiting\n\n\
                         Examples:\n\
                         {} -p 8080 --auth-file users.txt -l access.log\n\
                         {} -i 127.0.0.1 -p 8888 --auth-file users.txt -d\n\
                         {} -p 8080 --auth-file users.txt --max-read-rate 1024 --max-write-rate 512\n\
                         {} --hash-password \"mysecret\"\n\n\
                         Options:", program, program, program, program, program);
    
    let mut opts = Options::new();
    opts.optopt("i", "ip", "Listen address (default: 0.0.0.0)", "ADDRESS");
    opts.optopt("p", "port", "Listen port (default: 8888)", "PORT");
    opts.optopt("", "auth-file", "Authentication file (required)", "FILE");
    opts.optopt("l", "log", "Log file", "FILE");
    opts.optopt("", "max-attempts", "Max attempts before blocking (default: 5)", "NUMBER");
    opts.optopt("", "block-time", "Block time in seconds (default: 300)", "SECONDS");
    opts.optopt("", "hash-password", "Hash a password and exit", "PASSWORD");
    opts.optopt("", "write-cache", "Write cache size in MB (default: 0)", "MB");
    opts.optopt("", "max-read-rate", "Max read speed in Kb/s", "KB");
    opts.optopt("", "max-write-rate", "Max write speed in Kb/s", "KB");
    opts.optflag("d", "daemon", "Run in daemon mode");
    opts.optflag("v", "version", "Show version information");
    opts.optflag("h", "help", "Show this help");
    
    println!("{}", opts.usage(&brief));
}

fn print_version() {
    println!("minidav version {} ({})", VERSION, YEAR);
    println!("Author: {} - {}", AUTHOR, WEBSITE);
    println!("WebDAV server with COPY, MOVE, LOCK, UNLOCK support");
    println!("Features: Streaming, Range requests, Write Cache, Rate Limiting");
}

fn start_daemon_mode(args: &[String], program: &str) {
    let mut child_args = Vec::new();
    
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-d" {
            i += 1;
            continue;
        }
        child_args.push(args[i].clone());
        i += 1;
    }
    
    child_args.push(SECRET_DAEMON_FLAG.to_string());
    
    #[cfg(not(windows))]
    {
        use std::os::unix::process::CommandExt;
        
        let dev_null = match OpenOptions::new().write(true).open("/dev/null") {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Cannot open /dev/null: {}", e);
                process::exit(1);
            }
        };
        
        let mut cmd = Command::new("nohup");
        cmd.arg(program)
           .args(&child_args)
           .stdout(dev_null.try_clone().unwrap())
           .stderr(dev_null);
        
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                libc::signal(libc::SIGHUP, libc::SIG_IGN);
                Ok(())
            });
        }
        
        match cmd.spawn() {
            Ok(_child) => {
                process::exit(0);
            }
            Err(e) => {
                eprintln!("Error starting daemon: {}", e);
                process::exit(1);
            }
        }
    }
    
    #[cfg(windows)]
    {
        eprintln!("Daemon mode is not supported on Windows");
        process::exit(1);
    }
}

