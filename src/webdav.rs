use tiny_http::{Request, Response, StatusCode, Header};
use std::path::Path;
use std::fs;
use std::io::Cursor;
use crate::logging::Logger;
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{DateTime, Utc};

fn empty_response(status: u16) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(Vec::new()).with_status_code(StatusCode(status))
}

fn format_http_date(timestamp: SystemTime) -> String {
    let datetime: DateTime<Utc> = timestamp.into();
    datetime.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn format_iso_date(timestamp: SystemTime) -> String {
    let datetime: DateTime<Utc> = timestamp.into();
    datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub fn handle_propfind(request: &Request, physical_path: &Path, user: &str, remote_addr: &str, url: &str, logger: &Logger) -> Response<Cursor<Vec<u8>>> {
    if !physical_path.exists() {
        logger.access(remote_addr, user, "PROPFIND", url, 404, 0);
        return empty_response(404);
    }
    
    let depth = request.headers().iter()
        .find(|h| h.field.as_str().to_ascii_lowercase() == "depth")
        .map(|h| h.value.as_str())
        .unwrap_or("0");
    
    logger.debug(&format!("PROPFIND Depth: {}", depth));
    
    let host = request.headers().iter()
        .find(|h| h.field.as_str().to_ascii_lowercase() == "host")
        .map(|h| h.value.as_str())
        .unwrap_or("localhost:8880");
    
    let base_url = format!("http://{}", host);
    
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    xml.push_str("<D:multistatus xmlns:D=\"DAV:\">\n");
    
    add_propfind_response(&mut xml, &base_url, url, physical_path);
    
    if depth != "0" && physical_path.is_dir() {
        if let Ok(entries) = fs::read_dir(physical_path) {
            for entry in entries.flatten() {
                if let Ok(_file_type) = entry.file_type() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let child_url = if url.ends_with('/') {
                        format!("{}{}", url, name)
                    } else {
                        format!("{}/{}", url, name)
                    };
                    let child_path = physical_path.join(&name);
                    add_propfind_response(&mut xml, &base_url, &child_url, &child_path);
                }
            }
        }
    }
    
    xml.push_str("</D:multistatus>");
    
    logger.access(remote_addr, user, "PROPFIND", url, 207, xml.len() as u64);
    let mut response = Response::from_string(xml)
        .with_status_code(StatusCode(207));
    response.add_header(Header::from_bytes("Content-Type", "application/xml; charset=utf-8").unwrap());
    response.add_header(Header::from_bytes("DAV", "1,2").unwrap());
    response
}

fn add_propfind_response(xml: &mut String, base_url: &str, href: &str, path: &Path) {
    let full_href = if href.starts_with('/') {
        format!("{}{}", base_url, href)
    } else {
        format!("{}/{}", base_url, href)
    };
    
    xml.push_str("  <D:response>\n");
    xml.push_str(&format!("    <D:href>{}</D:href>\n", full_href));
    xml.push_str("    <D:propstat>\n");
    xml.push_str("      <D:prop>\n");
    
    if path.is_dir() {
        xml.push_str("        <D:resourcetype><D:collection/></D:resourcetype>\n");
    } else {
        xml.push_str("        <D:resourcetype/>\n");
    }
    
    if let Ok(metadata) = path.metadata() {
        if let Ok(modified) = metadata.modified() {
            xml.push_str(&format!("        <D:getlastmodified>{}</D:getlastmodified>\n", 
                                  format_http_date(modified)));
            xml.push_str(&format!("        <D:creationdate>{}</D:creationdate>\n", 
                                  format_iso_date(modified)));
        }
        
        if path.is_file() {
            xml.push_str(&format!("        <D:getcontentlength>{}</D:getcontentlength>\n", 
                                  metadata.len()));
            
            let content_type = match path.extension().and_then(|e| e.to_str()) {
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
            xml.push_str(&format!("        <D:getcontenttype>{}</D:getcontenttype>\n", content_type));
            
            if let Ok(modified) = metadata.modified() {
                if let Ok(duration) = modified.duration_since(UNIX_EPOCH) {
                    let etag = format!("\"{:x}-{:x}\"", metadata.len(), duration.as_secs());
                    xml.push_str(&format!("        <D:getetag>{}</D:getetag>\n", etag));
                }
            }
        } else {
            xml.push_str("        <D:getcontenttype>httpd/unix-directory</D:getcontenttype>\n");
        }
        
        xml.push_str("        <D:supportedlock>\n");
        xml.push_str("          <D:lockentry>\n");
        xml.push_str("            <D:lockscope><D:exclusive/></D:lockscope>\n");
        xml.push_str("            <D:locktype><D:write/></D:locktype>\n");
        xml.push_str("          </D:lockentry>\n");
        xml.push_str("        </D:supportedlock>\n");
        xml.push_str("        <D:lockdiscovery/>\n");
        
        let display_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        xml.push_str(&format!("        <D:displayname>{}</D:displayname>\n", display_name));
        
        let is_collection = if path.is_dir() { "1" } else { "0" };
        xml.push_str(&format!("        <D:iscollection>{}</D:iscollection>\n", is_collection));
        xml.push_str("        <D:ishidden>0</D:ishidden>\n");
    }
    
    xml.push_str("      </D:prop>\n");
    xml.push_str("      <D:status>HTTP/1.1 200 OK</D:status>\n");
    xml.push_str("    </D:propstat>\n");
    xml.push_str("  </D:response>\n");
}

pub fn handle_mkcol(request: &Request, physical_path: &Path, user: &str, remote_addr: &str, url: &str, logger: &Logger) -> Response<Cursor<Vec<u8>>> {
    if physical_path.exists() {
        logger.access(remote_addr, user, "MKCOL", url, 405, 0);
        return empty_response(405);
    }
    
    match fs::create_dir(physical_path) {
        Ok(_) => {
            logger.access(remote_addr, user, "MKCOL", url, 201, 0);
            empty_response(201)
        }
        Err(e) => {
            logger.error(&format!("Directory creation error {}: {}", physical_path.display(), e));
            logger.access(remote_addr, user, "MKCOL", url, 409, 0);
            empty_response(409)
        }
    }
}

pub fn handle_copy(request: &Request, physical_path: &Path, user: &str, remote_addr: &str, url: &str, logger: &Logger, root_path: &Path) -> Response<Cursor<Vec<u8>>> {
    if !physical_path.exists() {
        logger.access(remote_addr, user, "COPY", url, 404, 0);
        return empty_response(404);
    }
    
    let destination = match get_destination_header(request, root_path, logger) {
        Some(dest) => dest,
        None => {
            logger.access(remote_addr, user, "COPY", url, 400, 0);
            return empty_response(400);
        }
    };
    
    let overwrite = get_overwrite_header(request);
    
    if destination.exists() && !overwrite {
        logger.access(remote_addr, user, "COPY", url, 412, 0);
        return empty_response(412);
    }
    
    if destination.exists() && destination.is_dir() {
        logger.access(remote_addr, user, "COPY", url, 409, 0);
        return empty_response(409);
    }
    
    if let Some(parent) = destination.parent() {
        if !parent.exists() {
            if let Err(e) = fs::create_dir_all(parent) {
                logger.error(&format!("Directory creation error {}: {}", parent.display(), e));
                logger.access(remote_addr, user, "COPY", url, 500, 0);
                return empty_response(500);
            }
        }
    }
    
    let result = if physical_path.is_dir() {
        copy_dir_all(physical_path, &destination)
    } else {
        fs::copy(physical_path, &destination).map(|_| ())
    };
    
    match result {
        Ok(_) => {
            let status = if destination.exists() && overwrite { 204 } else { 201 };
            logger.access(remote_addr, user, "COPY", url, status, 0);
            empty_response(status)
        }
        Err(e) => {
            logger.error(&format!("Copy error from {} to {}: {}", physical_path.display(), destination.display(), e));
            logger.access(remote_addr, user, "COPY", url, 500, 0);
            empty_response(500)
        }
    }
}

pub fn handle_move(request: &Request, physical_path: &Path, user: &str, remote_addr: &str, url: &str, logger: &Logger, root_path: &Path) -> Response<Cursor<Vec<u8>>> {
    if !physical_path.exists() {
        logger.access(remote_addr, user, "MOVE", url, 404, 0);
        return empty_response(404);
    }
    
    let destination = match get_destination_header(request, root_path, logger) {
        Some(dest) => dest,
        None => {
            logger.access(remote_addr, user, "MOVE", url, 400, 0);
            return empty_response(400);
        }
    };
    
    let overwrite = get_overwrite_header(request);
    
    if destination.exists() && !overwrite {
        logger.access(remote_addr, user, "MOVE", url, 412, 0);
        return empty_response(412);
    }
    
    if destination.exists() && destination.is_dir() {
        logger.access(remote_addr, user, "MOVE", url, 409, 0);
        return empty_response(409);
    }
    
    if destination.exists() {
        if destination.is_dir() {
            if let Err(e) = fs::remove_dir_all(&destination) {
                logger.error(&format!("Directory removal error {}: {}", destination.display(), e));
                logger.access(remote_addr, user, "MOVE", url, 500, 0);
                return empty_response(500);
            }
        } else {
            if let Err(e) = fs::remove_file(&destination) {
                logger.error(&format!("File removal error {}: {}", destination.display(), e));
                logger.access(remote_addr, user, "MOVE", url, 500, 0);
                return empty_response(500);
            }
        }
    }
    
    if let Some(parent) = destination.parent() {
        if !parent.exists() {
            if let Err(e) = fs::create_dir_all(parent) {
                logger.error(&format!("Directory creation error {}: {}", parent.display(), e));
                logger.access(remote_addr, user, "MOVE", url, 500, 0);
                return empty_response(500);
            }
        }
    }
    
    match fs::rename(physical_path, &destination) {
        Ok(_) => {
            logger.access(remote_addr, user, "MOVE", url, 201, 0);
            empty_response(201)
        }
        Err(e) => {
            logger.error(&format!("Move error from {} to {}: {}", physical_path.display(), destination.display(), e));
            logger.access(remote_addr, user, "MOVE", url, 500, 0);
            empty_response(500)
        }
    }
}

fn get_destination_header(request: &Request, root_path: &Path, logger: &Logger) -> Option<std::path::PathBuf> {
    let dest_header = request.headers().iter()
        .find(|h| h.field.as_str().to_ascii_lowercase() == "destination")?;
    
    let dest_str = dest_header.value.as_str();
    logger.debug(&format!("Destination header: {}", dest_str));
    
    let uri = dest_str.split("://").nth(1)?;
    let path_start = uri.find('/')?;
    let url_path = &uri[path_start..];
    
    crate::server::build_physical_path(url_path, root_path)
}

fn get_overwrite_header(request: &Request) -> bool {
    request.headers().iter()
        .find(|h| h.field.as_str().to_ascii_lowercase() == "overwrite")
        .map(|h| h.value.as_str().to_ascii_lowercase() != "f")
        .unwrap_or(true)
}

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }
    
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        
        if ty.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    
    Ok(())
}

pub fn handle_options() -> Response<Cursor<Vec<u8>>> {
    let mut response = empty_response(200);
    response.add_header(Header::from_bytes("DAV", "1,2").unwrap());
    response.add_header(Header::from_bytes("Allow", "OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK").unwrap());
    response.add_header(Header::from_bytes("MS-Author-Via", "DAV").unwrap());
    response
}

