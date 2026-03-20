use tiny_http::{Server, Request, Response, StatusCode, Header};
use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::fs;
use std::fs::File;
use std::io::{self, BufReader, Read, Write, Cursor, Seek, SeekFrom};
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
    
    // On logue TOUTES les requêtes entrantes en DEBUG (utile pour déboguer si le GET ne sort pas)
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
    
    match method_str.as_str() {
        "GET" => {
            handle_get_and_respond(request, &physical_path, &user, &remote_addr, &url, &logger);
        },
        "PUT" => {
            let response = handle_put(&mut request, &physical_path, &user, &remote_addr, &url, &logger);
            let _ = request.respond(response);
        },
        "DELETE" => {
            let response = handle_delete(&physical_path, &user, &remote_addr, &url, &logger);
            let _ = request.respond(response);
        },
        "HEAD" => {
            let response = handle_head(&physical_path, &user, &remote_addr, &url, &logger);
            let _ = request.respond(response);
        },
        "PROPFIND" => {
            let response = webdav::handle_propfind(&request, &physical_path, &user, &remote_addr, &url, &logger);
            let _ = request.respond(response);
        },
        "MKCOL" => {
            let response = webdav::handle_mkcol(&request, &physical_path, &user, &remote_addr, &url, &logger);
            let _ = request.respond(response);
        },
        "COPY" => {
            let response = webdav::handle_copy(&request, &physical_path, &user, &remote_addr, &url, &logger, &root_path);
            let _ = request.respond(response);
        },
        "MOVE" => {
            let response = webdav::handle_move(&request, &physical_path, &user, &remote_addr, &url, &logger, &root_path);
            let _ = request.respond(response);
        },
        _ => {
            logger.access(&remote_addr, &user, &method_str, &url, 405, 0);
            let mut response = empty_response(405);
            response.add_header(Header::from_bytes("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL, COPY, MOVE").unwrap());
            let _ = request.respond(response);
        }
    };
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

pub fn build_physical_path(url: &str, root_path: &Path) -> Option<PathBuf> {
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

fn get_content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        // Texte
        Some("txt") => "text/plain",
        Some("html") | Some("htm") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("json") => "application/json",
        Some("xml") => "application/xml",
        Some("csv") => "text/csv",
        Some("md") | Some("markdown") => "text/markdown",
        
        // Images
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("webp") => "image/webp",
        Some("bmp") => "image/bmp",
        Some("ico") => "image/x-icon",
        Some("tiff") | Some("tif") => "image/tiff",
        
        // Audio
        Some("mp3") => "audio/mpeg",
        Some("ogg") => "audio/ogg",
        Some("wav") => "audio/wav",
        Some("flac") => "audio/flac",
        Some("aac") => "audio/aac",
        Some("m4a") => "audio/mp4",
        
        // Vidéo
        Some("mp4") => "video/mp4",
        Some("mkv") => "video/x-matroska",
        Some("webm") => "video/webm",
        Some("avi") => "video/x-msvideo",
        Some("mov") => "video/quicktime",
        Some("wmv") => "video/x-ms-wmv",
        Some("flv") => "video/x-flv",
        Some("m4v") => "video/x-m4v",
        Some("mpeg") | Some("mpg") => "video/mpeg",
        
        // Documents
        Some("pdf") => "application/pdf",
        Some("doc") => "application/msword",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("xls") => "application/vnd.ms-excel",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some("ppt") => "application/vnd.ms-powerpoint",
        Some("pptx") => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        
        // Archives
        Some("zip") => "application/zip",
        Some("tar") => "application/x-tar",
        Some("gz") => "application/gzip",
        Some("7z") => "application/x-7z-compressed",
        Some("rar") => "application/vnd.rar",
        
        // Fallback
        _ => "application/octet-stream",
    }
}

// Structure pour parser les ranges HTTP
struct ByteRange {
    start: u64,
    end: u64, // Inclusif
}

fn parse_range_header(range_header: &str, file_size: u64) -> Option<ByteRange> {
    if !range_header.starts_with("bytes=") {
        return None;
    }
    
    let range_spec = &range_header[6..];
    let parts: Vec<&str> = range_spec.split('-').collect();
    
    if parts.len() != 2 {
        return None;
    }
    
    let start = if parts[0].is_empty() {
        // Cas: bytes=-500 (les 500 derniers octets)
        let suffix_len = parts[1].parse::<u64>().ok()?;
        if suffix_len >= file_size {
            0
        } else {
            file_size - suffix_len
        }
    } else {
        parts[0].parse::<u64>().ok()?
    };
    
    let end = if parts[1].is_empty() {
        // Cas: bytes=500- (de 500 jusqu'à la fin)
        file_size - 1
    } else {
        parts[1].parse::<u64>().ok()?
    };
    
    // Validation des bornes
    if start > end || start >= file_size {
        return None;
    }
    
    Some(ByteRange {
        start,
        end: end.min(file_size - 1),
    })
}

fn handle_get_and_respond(request: Request, physical_path: &Path, user: &str, remote_addr: &str, url: &str, logger: &Logger) {
    if !physical_path.exists() {
        logger.access(remote_addr, user, "GET", url, 404, 0);
        let _ = request.respond(empty_response(404));
        return;
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
        let _ = request.respond(response);
    } else {
        match File::open(physical_path) {
            Ok(file) => {
                let metadata = match file.metadata() {
                    Ok(m) => m,
                    Err(e) => {
                        logger.error(&format!("Metadata error {}: {}", physical_path.display(), e));
                        logger.access(remote_addr, user, "GET", url, 500, 0);
                        let _ = request.respond(empty_response(500));
                        return;
                    }
                };
                
                let file_size = metadata.len();
                let content_type = get_content_type(physical_path);
                
                // LOG IMMÉDIAT (INFO) : On logue dès qu'on a les infos, avant de gérer le range
                // Cela garantit que le log apparaît même si le traitement Range échoue plus loin
                // et même en mode daemon (car c'est un 'info' implicite via logger.access plus bas)
                
                // Vérifier l'en-tête Range
                let range_header = request.headers().iter()
                    .find(|h| h.field.as_str().to_ascii_lowercase() == "range")
                    .map(|h| h.value.as_str());
                
                if let Some(range_str) = range_header {
                    // Gestion du Range Request (VLC, Seek, etc.)
                    if let Some(range) = parse_range_header(range_str, file_size) {
                        let content_length = range.end - range.start + 1;
                        
                        logger.debug(&format!("Range request parsed: {}-{}", range.start, range.end));
                        
                        // Ouvrir le fichier avec BufReader pour le streaming
                        let mut reader = BufReader::with_capacity(256 * 1024, file);
                        
                        // Se positionner au début du range
                        if let Err(e) = reader.seek(SeekFrom::Start(range.start)) {
                            logger.error(&format!("Seek error: {}", e));
                            logger.access(remote_addr, user, "GET", url, 500, 0);
                            let _ = request.respond(empty_response(500));
                            return;
                        }
                        
                        // Préparer les en-têtes spécifiques au Range
                        let content_range_header = format!("bytes {}-{}/{}", range.start, range.end, file_size);
                        
                        let mut response = Response::new(
                            StatusCode(206), // 206 Partial Content
                            vec![
                                Header::from_bytes("Content-Type", content_type).unwrap(),
                                Header::from_bytes("Content-Length", content_length.to_string().as_str()).unwrap(),
                                Header::from_bytes("Content-Range", content_range_header.as_str()).unwrap(),
                                Header::from_bytes("Accept-Ranges", "bytes").unwrap(),
                            ],
                            Box::new(reader.take(content_length)) as Box<dyn Read + Send>,
                            Some(content_length as usize),
                            None,
                        );
                        
                        // LOG ACCESS : Utilise la méthode access() qui écrit toujours (INFO/ACCESS)
                        logger.access(remote_addr, user, "GET", url, 206, content_length);
                        
                        if let Err(e) = request.respond(response) {
                            logger.error(&format!("Error sending Range response: {}", e));
                        }
                        return;
                    } else {
                        // Range invalide
                        logger.warning(&format!("Invalid range header: {}", range_str));
                        logger.access(remote_addr, user, "GET", url, 416, 0);
                        let mut response = empty_response(416);
                        response.add_header(Header::from_bytes("Content-Range", format!("bytes */{}", file_size).as_str()).unwrap());
                        let _ = request.respond(response);
                        return;
                    }
                }
                
                // Cas normal : pas de range, on envoie tout le fichier
                let reader = BufReader::with_capacity(256 * 1024, file);
                
                let mut response = Response::new(
                    StatusCode(200),
                    vec![
                        Header::from_bytes("Content-Type", content_type).unwrap(),
                        Header::from_bytes("Content-Length", file_size.to_string().as_str()).unwrap(),
                        Header::from_bytes("Accept-Ranges", "bytes").unwrap(),
                    ],
                    Box::new(reader) as Box<dyn Read + Send>,
                    Some(file_size as usize),
                    None,
                );
                
                // LOG ACCESS : Garantit l'écriture dans le fichier de log et la console (si pas daemon)
                logger.access(remote_addr, user, "GET", url, 200, file_size);
                
                if let Err(e) = request.respond(response) {
                    logger.error(&format!("Error sending GET response: {}", e));
                }
            }
            Err(e) => {
                logger.error(&format!("File open error {}: {}", physical_path.display(), e));
                logger.access(remote_addr, user, "GET", url, 500, 0);
                let _ = request.respond(empty_response(500));
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
                
                let content_type = get_content_type(physical_path);
                
                let mut response = empty_response(200);
                response.add_header(Header::from_bytes("Content-Type", content_type).unwrap());
                response.add_header(Header::from_bytes("Content-Length", size.to_string().as_str()).unwrap());
                response.add_header(Header::from_bytes("Accept-Ranges", "bytes").unwrap());
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
    if physical_path.exists() {
        if physical_path.is_dir() {
            logger.access(remote_addr, user, "PUT", url, 409, 0);
            return empty_response(409);
        }
        logger.debug(&format!("Overwriting existing file: {}", physical_path.display()));
    }
    
    if let Some(parent) = physical_path.parent() {
        if !parent.exists() {
            if let Err(e) = fs::create_dir_all(parent) {
                logger.error(&format!("Directory creation error {}: {}", parent.display(), e));
                logger.access(remote_addr, user, "PUT", url, 500, 0);
                return empty_response(500);
            }
        }
    }
    
    // STREAMING PUT : Ouverture du fichier en écriture directe
    let mut output_file = match File::create(physical_path) {
        Ok(f) => f,
        Err(e) => {
            logger.error(&format!("Cannot create file {}: {}", physical_path.display(), e));
            logger.access(remote_addr, user, "PUT", url, 500, 0);
            return empty_response(500);
        }
    };
    
    let reader = request.as_reader();
    let mut total_bytes: u64 = 0;
    let mut buffer = [0u8; 65536]; // Buffer 64 Ko
    
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break, // Fin du flux
            Ok(n) => {
                match output_file.write_all(&buffer[0..n]) {
                    Ok(_) => total_bytes += n as u64,
                    Err(e) => {
                        logger.error(&format!("Write error {}: {}", physical_path.display(), e));
                        logger.access(remote_addr, user, "PUT", url, 500, 0);
                        return empty_response(500);
                    }
                }
            }
            Err(e) => {
                logger.error(&format!("PUT read error: {}", e));
                logger.access(remote_addr, user, "PUT", url, 500, 0);
                return empty_response(500);
            }
        }
    }
    
    // S'assurer que tout est écrit physiquement sur le disque
    if let Err(e) = output_file.sync_all() {
        logger.error(&format!("Sync error {}: {}", physical_path.display(), e));
        logger.access(remote_addr, user, "PUT", url, 500, 0);
        return empty_response(500);
    }
    
    let status = if physical_path.exists() { 200 } else { 201 };
    logger.access(remote_addr, user, "PUT", url, status, total_bytes);
    logger.debug(&format!("PUT completed: {} bytes written to {}", total_bytes, physical_path.display()));
    empty_response(status)
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

