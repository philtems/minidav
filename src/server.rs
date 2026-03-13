use tiny_http::{Server, Request, Response, Method, StatusCode, Header};
use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::fs;
use std::io::Cursor;
use base64::prelude::*;
use percent_encoding::percent_decode_str;

use crate::auth::AuthManager;
use crate::logging::Logger;
use crate::webdav;
use crate::brute_force::BruteForceProtector;

pub struct DavServer {
    server: Server,
    auth_manager: Arc<AuthManager>,
    protector: Arc<BruteForceProtector>,
    logger: Arc<Logger>,
}

impl DavServer {
    pub fn new(addr: &str, port: u16, auth_manager: AuthManager, protector: Arc<BruteForceProtector>, logger: Logger) -> Result<Self, String> {
        let socket_addr = format!("{}:{}", addr, port);
        let server = Server::http(&socket_addr)
            .map_err(|e| {
                logger.error(&format!("Cannot start server on {}: {}", socket_addr, e));
                format!("Cannot start server on {}: {}", socket_addr, e)
            })?;
        
        logger.info(&format!("Server started on {}", socket_addr));
        
        Ok(DavServer {
            server,
            auth_manager: Arc::new(auth_manager),
            protector,
            logger: Arc::new(logger),
        })
    }
    
    pub fn run(&self) -> ! {
        self.logger.info("Server ready to accept connections");
        
        for request in self.server.incoming_requests() {
            let auth_manager = self.auth_manager.clone();
            let protector = self.protector.clone();
            let logger = self.logger.clone();
            
            std::thread::spawn(move || {
                handle_request(request, auth_manager, protector, logger);
            });
        }
        
        unreachable!()
    }
}

fn handle_request(mut request: Request, auth_manager: Arc<AuthManager>, protector: Arc<BruteForceProtector>, logger: Arc<Logger>) {
    let remote_addr = request.remote_addr().map(|a| a.to_string()).unwrap_or_else(|| "unknown".to_string());
    let method = request.method().clone();
    let method_str = method.as_str().to_string();
    let url = request.url().to_string();
    
    logger.debug(&format!("Request {} {} from {}", method_str, url, remote_addr));
    
    if method_str == "OPTIONS" {
        let response = webdav::handle_options();
        let _ = request.respond(response);
        return;
    }
    
    if protector.is_blocked(&remote_addr, &logger) {
        logger.access(&remote_addr, "-", &method_str, &url, 429, 0);
        let mut response = empty_response(429);
        response.add_header(Header::from_bytes("Retry-After", protector.get_block_time().to_string().as_str()).unwrap());
        let _ = request.respond(response);
        return;
    }
    
    let auth_result = authenticate_request(&request, &auth_manager, &protector, &remote_addr, &logger);
    
    let (user, root_path) = match auth_result {
        Ok((u, p)) => {
            protector.record_success(&remote_addr);
            (u, p)
        },
        Err(response) => {
            let _ = request.respond(response);
            return;
        }
    };
    
    let physical_path = match build_physical_path(&url, &root_path) {
        Some(p) => p,
        None => {
            logger.access(&remote_addr, &user, &method_str, &url, 404, 0);
            let response = empty_response(404);
            let _ = request.respond(response);
            return;
        }
    };
    
    logger.debug(&format!("Physical path: {}", physical_path.display()));
    
    let response = match method_str.as_str() {
        "GET" => handle_get(&physical_path, &user, &remote_addr, &url, &logger),
        "PUT" => handle_put(&mut request, &physical_path, &user, &remote_addr, &url, &logger),
        "DELETE" => handle_delete(&physical_path, &user, &remote_addr, &url, &logger),
        "HEAD" => handle_head(&physical_path, &user, &remote_addr, &url, &logger),
        "PROPFIND" => webdav::handle_propfind(&request, &physical_path, &user, &remote_addr, &url, &logger),
        "MKCOL" => webdav::handle_mkcol(&request, &physical_path, &user, &remote_addr, &url, &logger),
        _ => {
            logger.access(&remote_addr, &user, &method_str, &url, 405, 0);
            let mut response = empty_response(405);
            response.add_header(Header::from_bytes("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL").unwrap());
            response
        }
    };
    
    let _ = request.respond(response);
}

fn empty_response(status: u16) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(Vec::new()).with_status_code(StatusCode(status))
}

fn authenticate_request(request: &Request, auth_manager: &AuthManager, protector: &BruteForceProtector, remote_addr: &str, logger: &Logger) -> Result<(String, PathBuf), Response<Cursor<Vec<u8>>>> {
    let auth_header = match request.headers().iter()
        .find(|h| h.field.as_str().to_ascii_lowercase() == "authorization") {
        Some(h) => h.value.as_str().to_string(),
        None => {
            let mut response = empty_response(401);
            response.add_header(Header::from_bytes("WWW-Authenticate", "Basic realm=\"WebDAV\"").unwrap());
            return Err(response);
        }
    };
    
    if !auth_header.starts_with("Basic ") {
        let mut response = empty_response(401);
        response.add_header(Header::from_bytes("WWW-Authenticate", "Basic realm=\"WebDAV\"").unwrap());
        return Err(response);
    }
    
    let base64_part = &auth_header[6..];
    let decoded = match BASE64_STANDARD.decode(base64_part) {
        Ok(d) => d,
        Err(e) => {
            logger.debug(&format!("Base64 decode error: {}", e));
            protector.record_failure(remote_addr, logger);
            return Err(empty_response(400));
        }
    };
    
    let credentials = match String::from_utf8(decoded) {
        Ok(s) => s,
        Err(e) => {
            logger.debug(&format!("UTF-8 error: {}", e));
            protector.record_failure(remote_addr, logger);
            return Err(empty_response(400));
        }
    };
    
    let parts: Vec<&str> = credentials.splitn(2, ':').collect();
    if parts.len() != 2 {
        protector.record_failure(remote_addr, logger);
        return Err(empty_response(400));
    }
    
    let login = parts[0];
    let password = parts[1];
    
    match auth_manager.authenticate(login, password) {
        Some(user) => Ok((user.login.clone(), user.root_path.clone())),
        None => {
            protector.record_failure(remote_addr, logger);
            let mut response = empty_response(401);
            response.add_header(Header::from_bytes("WWW-Authenticate", "Basic realm=\"WebDAV\"").unwrap());
            Err(response)
        }
    }
}

fn build_physical_path(url: &str, root_path: &Path) -> Option<PathBuf> {
    let mut current = url.to_string();
    let mut previous;
    let mut iterations = 0;
    const MAX_ITERATIONS: u32 = 10;
    
    loop {
        iterations += 1;
        if iterations > MAX_ITERATIONS {
            eprintln!("Too many decode iterations for: {}", url);
            return None;
        }
        
        previous = current.clone();
        current = match percent_decode_str(&current).decode_utf8() {
            Ok(d) => d.to_string(),
            Err(_) => break,
        };
        
        if current == previous {
            break;
        }
    }
    
    let cleaned_path = clean_path(&current);
    
    let mut physical = root_path.to_path_buf();
    
    if cleaned_path.starts_with('/') {
        if cleaned_path.len() > 1 {
            let path_part = &cleaned_path[1..];
            let path_part = path_part.replace("%2F", "/");
            physical.push(path_part);
        }
    } else if !cleaned_path.is_empty() {
        let path_part = cleaned_path.replace("%2F", "/");
        physical.push(path_part);
    }
    
    if physical.starts_with(root_path) {
        Some(physical)
    } else {
        eprintln!("Path outside root: {} -> {}", cleaned_path, physical.display());
        None
    }
}

fn clean_path(path: &str) -> String {
    let mut parts = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => continue,
            ".." => {
                parts.pop();
            }
            _ => parts.push(component),
        }
    }
    
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn handle_get(physical_path: &Path, user: &str, remote_addr: &str, url: &str, logger: &Logger) -> Response<Cursor<Vec<u8>>> {
    if !physical_path.exists() {
        logger.access(remote_addr, user, "GET", url, 404, 0);
        return empty_response(404);
    }
    
    if physical_path.is_dir() {
        let mut content = String::new();
        content.push_str("<!DOCTYPE html>\n<html>\n<head>\n<title>Index of ");
        content.push_str(url);
        content.push_str("</title>\n");
        content.push_str("<meta charset=\"UTF-8\">\n");
        content.push_str("</head>\n<body>\n<h1>Index of ");
        content.push_str(url);
        content.push_str("</h1>\n<hr>\n<ul>\n");
        
        if url != "/" {
            let parent = if url.ends_with('/') {
                let mut p = url.to_string();
                p.pop();
                let last_slash = p.rfind('/').unwrap_or(0);
                if last_slash == 0 {
                    "/".to_string()
                } else {
                    p[..last_slash+1].to_string()
                }
            } else {
                let last_slash = url.rfind('/').unwrap_or(0);
                if last_slash == 0 {
                    "/".to_string()
                } else {
                    url[..last_slash+1].to_string()
                }
            };
            content.push_str(&format!("<li><a href=\"{}\">../</a></li>\n", parent));
        }
        
        if let Ok(entries) = fs::read_dir(physical_path) {
            let mut entries: Vec<_> = entries.filter_map(|e| e.ok()).collect();
            entries.sort_by_key(|e| e.file_name());
            
            for entry in entries {
                if let Ok(file_type) = entry.file_type() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    
                    let display_name = if file_type.is_dir() { 
                        format!("{}/", name) 
                    } else { 
                        name.clone() 
                    };
                    
                    let href = if url.ends_with('/') {
                        format!("{}{}", url, name)
                    } else {
                        format!("{}/{}", url, name)
                    };
                    
                    let href_encoded = percent_encoding::utf8_percent_encode(&href, percent_encoding::NON_ALPHANUMERIC).to_string();
                    
                    content.push_str(&format!("<li><a href=\"{}\">{}</a></li>\n", 
                                             href_encoded, display_name));
                }
            }
        }
        
        content.push_str("</ul>\n<hr>\n</body>\n</html>");
        
        logger.access(remote_addr, user, "GET", url, 200, content.len() as u64);
        
        let mut response = Response::from_string(content)
            .with_status_code(StatusCode(200));
        response.add_header(Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap());
        response
    } else {
        match fs::read(physical_path) {
            Ok(data) => {
                let size = data.len() as u64;
                logger.access(remote_addr, user, "GET", url, 200, size);
                
                let content_type = match physical_path.extension().and_then(|e| e.to_str()) {
                    Some("txt") => "text/plain",
                    Some("html") | Some("htm") => "text/html",
                    Some("css") => "text/css",
                    Some("js") => "application/javascript",
                    Some("json") => "application/json",
                    Some("png") => "image/png",
                    Some("jpg") | Some("jpeg") => "image/jpeg",
                    Some("gif") => "image/gif",
                    Some("pdf") => "application/pdf",
                    _ => "application/octet-stream",
                };
                
                let mut response = Response::from_data(data)
                    .with_status_code(StatusCode(200));
                response.add_header(Header::from_bytes("Content-Type", content_type).unwrap());
                response
            }
            Err(e) => {
                logger.access(remote_addr, user, "GET", url, 500, 0);
                logger.error(&format!("File read error {}: {}", physical_path.display(), e));
                empty_response(500)
            }
        }
    }
}

fn handle_head(physical_path: &Path, user: &str, remote_addr: &str, url: &str, logger: &Logger) -> Response<Cursor<Vec<u8>>> {
    if !physical_path.exists() {
        logger.access(remote_addr, user, "HEAD", url, 404, 0);
        return empty_response(404);
    }
    
    if physical_path.is_dir() {
        logger.access(remote_addr, user, "HEAD", url, 200, 0);
        let mut response = empty_response(200);
        response.add_header(Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap());
        response
    } else {
        match physical_path.metadata() {
            Ok(metadata) => {
                let size = metadata.len();
                logger.access(remote_addr, user, "HEAD", url, 200, size);
                
                let content_type = match physical_path.extension().and_then(|e| e.to_str()) {
                    Some("txt") => "text/plain",
                    Some("html") | Some("htm") => "text/html",
                    Some("css") => "text/css",
                    Some("js") => "application/javascript",
                    Some("json") => "application/json",
                    Some("png") => "image/png",
                    Some("jpg") | Some("jpeg") => "image/jpeg",
                    Some("gif") => "image/gif",
                    Some("pdf") => "application/pdf",
                    _ => "application/octet-stream",
                };
                
                let mut response = empty_response(200);
                response.add_header(Header::from_bytes("Content-Type", content_type).unwrap());
                response.add_header(Header::from_bytes("Content-Length", size.to_string().as_str()).unwrap());
                response
            }
            Err(e) => {
                logger.access(remote_addr, user, "HEAD", url, 500, 0);
                logger.error(&format!("Metadata error {}: {}", physical_path.display(), e));
                empty_response(500)
            }
        }
    }
}

fn handle_put(request: &mut Request, physical_path: &Path, user: &str, remote_addr: &str, url: &str, logger: &Logger) -> Response<Cursor<Vec<u8>>> {
    // Vérifier si le chemin existe déjà et si c'est un dossier
    if physical_path.exists() {
        if physical_path.is_dir() {
            logger.access(remote_addr, user, "PUT", url, 409, 0);
            return empty_response(409);
        }
        logger.debug(&format!("Overwriting existing file: {}", physical_path.display()));
    }
    
    // Créer les dossiers parents si nécessaire
    if let Some(parent) = physical_path.parent() {
        if !parent.exists() {
            if let Err(e) = fs::create_dir_all(parent) {
                logger.error(&format!("Directory creation error {}: {}", parent.display(), e));
                logger.access(remote_addr, user, "PUT", url, 500, 0);
                return empty_response(500);
            }
        }
    }
    
    // Lire toutes les données de la requête
    let mut data = Vec::new();
    let mut reader = request.as_reader();
    
    // Lire en boucle jusqu'à épuisement des données
    loop {
        let mut buffer = [0; 16384]; // Buffer de 16KB
        match reader.read(&mut buffer) {
            Ok(0) => break, // Fin des données
            Ok(n) => data.extend_from_slice(&buffer[0..n]),
            Err(e) => {
                logger.error(&format!("PUT data read error: {}", e));
                logger.access(remote_addr, user, "PUT", url, 500, 0);
                return empty_response(500);
            }
        }
    }
    
    logger.debug(&format!("PUT data size: {} bytes", data.len()));
    
    // Écrire le fichier
    match fs::write(physical_path, &data) {
        Ok(_) => {
            // 201 Created pour nouveau fichier, 200 OK pour mise à jour
            let status = if physical_path.exists() { 200 } else { 201 };
            logger.access(remote_addr, user, "PUT", url, status, data.len() as u64);
            empty_response(status)
        }
        Err(e) => {
            logger.error(&format!("File write error {}: {}", physical_path.display(), e));
            logger.access(remote_addr, user, "PUT", url, 500, 0);
            empty_response(500)
        }
    }
}

fn handle_delete(physical_path: &Path, user: &str, remote_addr: &str, url: &str, logger: &Logger) -> Response<Cursor<Vec<u8>>> {
    if !physical_path.exists() {
        logger.access(remote_addr, user, "DELETE", url, 404, 0);
        return empty_response(404);
    }
    
    let result = if physical_path.is_dir() {
        match fs::read_dir(physical_path) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    logger.access(remote_addr, user, "DELETE", url, 409, 0);
                    return empty_response(409);
                }
                fs::remove_dir(physical_path)
            }
            Err(e) => Err(e),
        }
    } else {
        fs::remove_file(physical_path)
    };
    
    match result {
        Ok(_) => {
            logger.access(remote_addr, user, "DELETE", url, 204, 0);
            empty_response(204)
        }
        Err(e) => {
            logger.error(&format!("Deletion error {}: {}", physical_path.display(), e));
            logger.access(remote_addr, user, "DELETE", url, 500, 0);
            empty_response(500)
        }
    }
}

