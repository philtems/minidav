use tiny_http::{Server, Request, Response, StatusCode, Header};
use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::fs;
use std::fs::File;
use std::io::{self, BufReader, Read, Write, Cursor, Seek, SeekFrom};

use crate::auth::AuthManager;
use crate::logging::Logger;
use crate::webdav;
use crate::brute_force::BruteForceProtector;
use crate::webdav::LockManager;
use base64::prelude::*;
use percent_encoding::percent_decode_str;

pub struct DavServer {
    server: Server,
    auth_manager: Arc<AuthManager>,
    protector: Arc<BruteForceProtector>,
    lock_manager: Arc<LockManager>,
    logger: Arc<Logger>,
    write_cache_bytes: usize,
}

impl DavServer {
    pub fn new(
        addr: &str, port: u16,
        auth_manager: AuthManager, protector: Arc<BruteForceProtector>,
        lock_manager: Arc<LockManager>, logger: Logger,
        write_cache_mb: usize
    ) -> Result<Self, String> {
        let socket = format!("{}:{}", addr, port);
        let server = Server::http(&socket).map_err(|e| format!("Bind error: {}", e))?;
        logger.info(&format!("Server started on {}", socket));
        
        Ok(DavServer {
            server,
            auth_manager: Arc::new(auth_manager),
            protector,
            lock_manager,
            logger: Arc::new(logger),
            write_cache_bytes: write_cache_mb * 1024 * 1024,
        })
    }

    pub fn run(self) -> ! {
        let am = self.auth_manager;
        let prot = self.protector;
        let lock = self.lock_manager;
        let log = self.logger;
        let cache = self.write_cache_bytes;

        for request in self.server.incoming_requests() {
            let am = am.clone();
            let prot = prot.clone();
            let lock = lock.clone();
            let log = log.clone();
            let cache = cache;

            std::thread::spawn(move || {
                handle_request(request, am, prot, lock, log, cache);
            });
        }
        unreachable!()
    }
}

fn handle_request(mut request: Request, auth_manager: Arc<AuthManager>, protector: Arc<BruteForceProtector>, lock_manager: Arc<LockManager>, logger: Arc<Logger>, write_cache_bytes: usize) {
    let remote = request.remote_addr().map(|a| a.to_string()).unwrap_or("unknown".into());
    let method = request.method().to_string();
    let url = request.url().to_string();

    if method == "OPTIONS" { let _ = request.respond(webdav::handle_options()); return; }
    
    let (user, root_path) = match authenticate(&request, &auth_manager, &protector, &remote, &logger) {
        Ok(u) => u,
        Err(r) => { let _ = request.respond(r); return; }
    };
    
    let phys_path = match build_physical_path(&url, &root_path) {
        Some(p) => p,
        None => {
            logger.access(&remote, &user, &method, &url, 404, 0);
            let _ = request.respond(Response::from_data(Vec::new()).with_status_code(StatusCode(404)));
            return;
        }
    };

    match method.as_str() {
        "GET" => handle_get(request, &phys_path, &user, &remote, &url, &logger),
        "PUT" => {
            let lock_token = request.headers().iter().find(|h| h.field.as_str().to_ascii_lowercase() == "if").map(|h| h.value.as_str());
            if let Err(_) = lock_manager.check_lock(&phys_path, lock_token) {
                logger.access(&remote, &user, "PUT", &url, 423, 0);
                let _ = request.respond(Response::from_string("Locked").with_status_code(StatusCode(423)));
                return;
            }
            let response = handle_put(&mut request, &phys_path, &user, &remote, &url, &logger, write_cache_bytes);
            let _ = request.respond(response);
        },
        "LOCK" => {
            let r = webdav::handle_lock(&request, &phys_path, &user, &remote, &url, &logger, lock_manager);
            let _ = request.respond(r);
        },
        "UNLOCK" => {
            let r = webdav::handle_unlock(&request, &phys_path, &user, &remote, &url, &logger, lock_manager);
            let _ = request.respond(r);
        },
        "DELETE" => {
             if let Err(_) = lock_manager.check_lock(&phys_path, None) {
                 let _ = request.respond(Response::from_data(Vec::new()).with_status_code(StatusCode(423)));
                 return;
             }
             let r = handle_delete(&phys_path, &user, &remote, &url, &logger);
             let _ = request.respond(r);
        },
        "PROPFIND" => {
            let r = webdav::handle_propfind(&request, &phys_path, &user, &remote, &url, &logger);
            let _ = request.respond(r);
        },
        "MKCOL" => {
            let r = webdav::handle_mkcol(&request, &phys_path, &user, &remote, &url, &logger);
            let _ = request.respond(r);
        },
        "COPY" => {
            let r = webdav::handle_copy(&request, &phys_path, &user, &remote, &url, &logger, &root_path);
            let _ = request.respond(r);
        },
        "MOVE" => {
            let r = webdav::handle_move(&request, &phys_path, &user, &remote, &url, &logger, &root_path);
            let _ = request.respond(r);
        },
        "HEAD" => {
            let r = handle_head(&phys_path, &user, &remote, &url, &logger);
            let _ = request.respond(r);
        },
        _ => {
            let _ = request.respond(Response::from_data(Vec::new()).with_status_code(StatusCode(405)));
        }
    }
}

fn authenticate(req: &Request, am: &AuthManager, prot: &BruteForceProtector, remote: &str, logger: &Logger) -> Result<(String, PathBuf), Response<Cursor<Vec<u8>>>> {
    let auth = req.headers().iter().find(|h| h.field.as_str().to_ascii_lowercase() == "authorization");
    let val = match auth { Some(h) => h.value.as_str(), None => {
        let mut r = Response::from_data(Vec::new()).with_status_code(StatusCode(401));
        r.add_header(Header::from_bytes("WWW-Authenticate", "Basic realm=\"WebDAV\"").unwrap());
        return Err(r);
    }};
    if !val.starts_with("Basic ") {
        let mut r = Response::from_data(Vec::new()).with_status_code(StatusCode(401));
        r.add_header(Header::from_bytes("WWW-Authenticate", "Basic realm=\"WebDAV\"").unwrap());
        return Err(r);
    }
    let decoded = match BASE64_STANDARD.decode(&val[6..]) { Ok(d) => d, Err(_) => { prot.record_failure(remote, logger); return Err(Response::from_data(Vec::new()).with_status_code(StatusCode(400))); }};
    let creds = match String::from_utf8(decoded) { Ok(s) => s, Err(_) => { prot.record_failure(remote, logger); return Err(Response::from_data(Vec::new()).with_status_code(StatusCode(400))); }};
    let mut parts = creds.splitn(2, ':');
    let login = parts.next().unwrap_or("");
    let pass = parts.next().unwrap_or("");
    match am.authenticate(login, pass) {
        Some(u) => { prot.record_success(remote); Ok((u.login.clone(), u.root_path.clone())) }
        None => { prot.record_failure(remote, logger); 
            let mut r = Response::from_data(Vec::new()).with_status_code(StatusCode(401));
            r.add_header(Header::from_bytes("WWW-Authenticate", "Basic realm=\"WebDAV\"").unwrap());
            Err(r) 
        }
    }
}

pub fn build_physical_path(url: &str, root: &Path) -> Option<PathBuf> {
    let decoded = percent_decode_str(url).decode_utf8().ok()?.to_string();
    let clean = decoded.split('/').filter(|s| !s.is_empty() && *s != ".").fold(Vec::new(), |mut acc, c| {
        if c == ".." { acc.pop(); } else { acc.push(c); }
        acc
    });
    let mut p = root.to_path_buf();
    for part in clean { p.push(part); }
    if p.starts_with(root) { Some(p) } else { None }
}

fn handle_get(request: Request, path: &Path, user: &str, remote: &str, url: &str, logger: &Logger) {
    if !path.exists() {
        logger.access(remote, user, "GET", url, 404, 0);
        let _ = request.respond(Response::from_data(Vec::new()).with_status_code(StatusCode(404)));
        return;
    }
    if path.is_dir() {
        let mut html = format!("<html><body><h1>Index of {}</h1><ul>", url);
        if let Ok(entries) = fs::read_dir(path) {
            for e in entries.flatten() {
                if let Ok(name) = e.file_name().into_string() {
                    let t = if e.file_type().map(|f| f.is_dir()).unwrap_or(false) { "/" } else { "" };
                    html.push_str(&format!("<li><a href=\"{}{}\">{}</a></li>", name, t, name));
                }
            }
        }
        html.push_str("</ul></body></html>");
        let _ = request.respond(Response::from_string(html).with_status_code(StatusCode(200)));
        return;
    }

    match File::open(path) {
        Ok(file) => {
            let meta = file.metadata().unwrap();
            let len = meta.len();
            
            // Gestion des Range Requests (nécessaire pour le streaming vidéo)
            let range = request.headers().iter().find(|h| h.field.as_str().to_ascii_lowercase() == "range").map(|h| h.value.as_str());
            
            if let Some(r_str) = range {
                if let Some(r) = parse_range_header(r_str, len) {
                    let content_length = r.end - r.start + 1;
                    let mut reader = BufReader::with_capacity(256 * 1024, file);
                    if let Err(e) = reader.seek(SeekFrom::Start(r.start)) {
                        logger.error(&format!("Seek error: {}", e));
                        let _ = request.respond(Response::from_data(Vec::new()).with_status_code(StatusCode(500)));
                        return;
                    }
                    // Stream direct sans rate limiting
                    let mut resp = Response::new(
                        StatusCode(206),
                        vec![
                            Header::from_bytes("Content-Type", "application/octet-stream").unwrap(),
                            Header::from_bytes("Content-Length", content_length.to_string().as_str()).unwrap(),
                            Header::from_bytes("Content-Range", format!("bytes {}-{}/{}", r.start, r.end, len).as_str()).unwrap(),
                            Header::from_bytes("Accept-Ranges", "bytes").unwrap(),
                        ],
                        Box::new(reader.take(content_length)) as Box<dyn Read + Send>,
                        Some(content_length as usize),
                        None,
                    );
                    logger.access(remote, user, "GET", url, 206, content_length);
                    let _ = request.respond(resp);
                    return;
                }
            }
            
            // Cas normal (pas de range) - Stream direct
            let reader = BufReader::with_capacity(256 * 1024, file);
            let mut resp = Response::new(
                StatusCode(200),
                vec![
                    Header::from_bytes("Content-Type", "application/octet-stream").unwrap(),
                    Header::from_bytes("Content-Length", len.to_string().as_str()).unwrap(),
                    Header::from_bytes("Accept-Ranges", "bytes").unwrap(),
                ],
                Box::new(reader) as Box<dyn Read + Send>,
                Some(len as usize),
                None,
            );
            logger.access(remote, user, "GET", url, 200, len);
            let _ = request.respond(resp);
        }
        Err(_) => {
            logger.access(remote, user, "GET", url, 500, 0);
            let _ = request.respond(Response::from_data(Vec::new()).with_status_code(StatusCode(500)));
        }
    }
}

struct ByteRange { start: u64, end: u64 }
fn parse_range_header(range_header: &str, file_size: u64) -> Option<ByteRange> {
    if !range_header.starts_with("bytes=") { return None; }
    let range_spec = &range_header[6..];
    let parts: Vec<&str> = range_spec.split('-').collect();
    if parts.len() != 2 { return None; }
    let start = if parts[0].is_empty() {
        let suffix = parts[1].parse::<u64>().ok()?;
        if suffix >= file_size { 0 } else { file_size - suffix }
    } else { parts[0].parse::<u64>().ok()? };
    let end = if parts[1].is_empty() { file_size - 1 } else { parts[1].parse::<u64>().ok()? };
    if start > end || start >= file_size { return None; }
    Some(ByteRange { start, end: end.min(file_size - 1) })
}

fn handle_put(req: &mut Request, path: &Path, user: &str, remote: &str, url: &str, logger: &Logger, cache_limit: usize) -> Response<Cursor<Vec<u8>>> {
    if path.is_dir() { return Response::from_data(Vec::new()).with_status_code(StatusCode(409)); }
    if let Some(p) = path.parent() { let _ = fs::create_dir_all(p); }

    let mut written: u64 = 0;
    let mut buf = [0u8; 65536];
    let reader = req.as_reader();

    // Mode Streaming (cache_limit == 0) ou Cache (cache_limit > 0)
    // DANS TOUS LES CAS : Pas de rate limiting, écriture au rythme du réseau/disque
    if cache_limit == 0 {
        let mut file = match File::create(path) { Ok(f) => f, Err(_) => return Response::from_data(Vec::new()).with_status_code(StatusCode(500)) };
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(_) = file.write_all(&buf[..n]) { return Response::from_data(Vec::new()).with_status_code(StatusCode(500)); }
                    written += n as u64;
                }
                Err(_) => return Response::from_data(Vec::new()).with_status_code(StatusCode(500)),
            }
        }
        let _ = file.sync_all();
    } else {
        // Mode avec cache mémoire pour les petits fichiers
        let mut mem = Vec::new();
        let mut file: Option<File> = None;
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if file.is_none() && mem.len() + n <= cache_limit {
                        mem.extend_from_slice(&buf[..n]);
                    } else {
                        if file.is_none() {
                            file = match File::create(path) { 
                                Ok(f) => { 
                                    let mut f_mut = f;
                                    let _ = f_mut.write_all(&mem); 
                                    Some(f_mut) 
                                }, 
                                Err(_) => return Response::from_data(Vec::new()).with_status_code(StatusCode(500)) 
                            };
                            mem.clear();
                        }
                        if let Some(ref mut f) = file {
                            if let Err(_) = f.write_all(&buf[..n]) { return Response::from_data(Vec::new()).with_status_code(StatusCode(500)); }
                        }
                    }
                    written += n as u64;
                }
                Err(_) => return Response::from_data(Vec::new()).with_status_code(StatusCode(500)),
            }
        }
        if let Some(f) = file { let _ = f.sync_all(); } 
        else if !mem.is_empty() { 
            if let Ok(mut f) = File::create(path) { let _ = f.write_all(&mem); let _ = f.sync_all(); } 
        }
    }
    logger.access(remote, user, "PUT", url, 201, written);
    Response::from_data(Vec::new()).with_status_code(StatusCode(201))
}

fn handle_head(path: &Path, _user: &str, remote: &str, url: &str, logger: &Logger) -> Response<Cursor<Vec<u8>>> {
    if !path.exists() { return Response::from_data(Vec::new()).with_status_code(StatusCode(404)); }
    let m = path.metadata().ok();
    let mut r = Response::from_data(Vec::new()).with_status_code(StatusCode(200));
    if let Some(meta) = m {
        r.add_header(Header::from_bytes("Content-Length", meta.len().to_string().as_str()).unwrap());
        logger.access(remote, _user, "HEAD", url, 200, meta.len());
    }
    r
}

fn handle_delete(path: &Path, user: &str, remote: &str, url: &str, logger: &Logger) -> Response<Cursor<Vec<u8>>> {
    if !path.exists() { return Response::from_data(Vec::new()).with_status_code(StatusCode(404)); }
    let res = if path.is_dir() {
        match fs::read_dir(path) {
            Ok(mut entries) => if entries.next().is_some() { return Response::from_data(Vec::new()).with_status_code(StatusCode(409)); } else { fs::remove_dir(path) },
            Err(e) => Err(e),
        }
    } else { fs::remove_file(path) };
    match res {
        Ok(_) => { logger.access(remote, user, "DELETE", url, 204, 0); Response::from_data(Vec::new()).with_status_code(StatusCode(204)) }
        Err(_) => { logger.access(remote, user, "DELETE", url, 500, 0); Response::from_data(Vec::new()).with_status_code(StatusCode(500)) }
    }
}

