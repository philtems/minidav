use tiny_http::{Request, Response, StatusCode, Header};
use std::path::{Path, PathBuf};
use std::fs;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use crate::logging::Logger;
use chrono::{DateTime, Utc};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

// --- CORRECTION ICI ---
// On définit un ensemble de caractères "sûrs" qui ne seront JAMAIS encodés.
// On part de NON_ALPHANUMERIC et on RETIRE :
// - b'/' (séparateur de chemin, déjà géré par la logique)
// - b'-' (tiret)
// - b'_' (underscore)
// - b'.' (point, pour les extensions)
// - b'~' (tilde, souvent utilisé)
const SAFE_URL_CHARS: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');
// ----------------------

// --- Gestionnaire de Verrous (Lock Manager) ---

struct LockEntry {
    token: String,
    owner: String,
    expires_at: u64, // Timestamp UNIX
    path: PathBuf,
}

pub struct LockManager {
    locks: Mutex<HashMap<String, LockEntry>>,
    logger: Logger,
}

impl LockManager {
    pub fn new(logger: Logger) -> Arc<Self> {
        let manager = Arc::new(LockManager {
            locks: Mutex::new(HashMap::new()),
            logger,
        });
        
        let mgr_clone = manager.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(60));
                mgr_clone.cleanup_expired();
            }
        });
        
        manager
    }
    
    fn cleanup_expired(&self) {
        let mut locks = self.locks.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let before = locks.len();
        locks.retain(|_, entry| entry.expires_at > now);
        if before != locks.len() {
            self.logger.debug(&format!("Lock cleanup: removed {} expired locks", before - locks.len()));
        }
    }
    
    pub fn create_lock(&self, path: &Path, owner: &str) -> String {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let expires = now + 3600;
        
        let token = format!("<opaquelocktoken:{}-{}>", owner, now);
        
        let mut locks = self.locks.lock().unwrap();
        locks.retain(|_, entry| !(entry.path == path && entry.owner == owner));
        
        locks.insert(token.clone(), LockEntry {
            token: token.clone(),
            owner: owner.to_string(),
            expires_at: expires,
            path: path.to_path_buf(),
        });
        
        self.logger.debug(&format!("Lock created: {} for {}", token, path.display()));
        token
    }
    
    pub fn check_lock(&self, path: &Path, token_opt: Option<&str>) -> Result<(), String> {
        let locks = self.locks.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        for entry in locks.values() {
            if entry.path == path && entry.expires_at > now {
                if let Some(token) = token_opt {
                    if entry.token == token {
                        return Ok(());
                    }
                }
                return Err(format!("Locked by {}", entry.owner));
            }
        }
        Ok(())
    }
    
    pub fn remove_lock(&self, token: &str) -> bool {
        let mut locks = self.locks.lock().unwrap();
        if let Some(entry) = locks.get(token) {
            if entry.expires_at > SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() {
                locks.remove(token);
                self.logger.debug(&format!("Lock removed: {}", token));
                return true;
            }
        }
        false
    }
}

// --- Fonctions WebDAV ---

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
    
    let host = request.headers().iter()
        .find(|h| h.field.as_str().to_ascii_lowercase() == "host")
        .map(|h| h.value.as_str())
        .unwrap_or("localhost");
    let base_url = format!("http://{}", host);
    
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">\n");
    
    // Pour la racine, on utilise l'URL telle quelle (elle vient du client, donc déjà correcte)
    // Mais on s'assure qu'elle est propre si besoin (optionnel, souvent inutile pour la racine)
    if let Err(e) = add_propfind_response(&mut xml, &base_url, url, physical_path) {
        logger.warning(&format!("Propfind error on root {}: {}", physical_path.display(), e));
    }
    
    if depth != "0" && physical_path.is_dir() {
        if let Ok(entries) = fs::read_dir(physical_path) {
            for entry in entries.flatten() {
                let name = match entry.file_name().into_string() {
                    Ok(n) => n,
                    Err(bad) => {
                        logger.warning(&format!("Skipping file with invalid UTF-8 name: {:?}", bad));
                        continue;
                    }
                };
                
                // ENCODAGE CIBLÉ : Seul le nom du fichier est encodé avec SAFE_URL_CHARS
                // Cela préservera les tirets, underscores et points.
                let encoded_name = utf8_percent_encode(&name, SAFE_URL_CHARS).to_string();
                
                let child_url = if url.ends_with('/') { 
                    format!("{}{}", url, encoded_name) 
                } else { 
                    format!("{}/{}", url, encoded_name) 
                };
                
                let child_path = physical_path.join(&name);
                
                if !child_path.starts_with(physical_path) { continue; }
                
                if let Err(e) = add_propfind_response(&mut xml, &base_url, &child_url, &child_path) {
                    logger.debug(&format!("Skipping entry {} due to error: {}", name, e));
                    continue;
                }
            }
        }
    }
    
    xml.push_str("</D:multistatus>");
    logger.access(remote_addr, user, "PROPFIND", url, 207, xml.len() as u64);
    
    let mut response = Response::from_string(xml).with_status_code(StatusCode(207));
    response.add_header(Header::from_bytes("Content-Type", "application/xml; charset=utf-8").unwrap());
    response.add_header(Header::from_bytes("DAV", "1,2").unwrap());
    response
}

fn add_propfind_response(xml: &mut String, base_url: &str, href: &str, path: &Path) -> Result<(), String> {
    // L'URL 'href' arrive déjà encodée segment par segment depuis handle_propfind.
    // On ne la ré-encode pas entièrement pour éviter de doubler les '%' si l'URL est déjà propre.
    // On l'utilise telle quelle pour construire le lien complet.
    
    let full_href = if href.starts_with('/') { 
        format!("{}{}", base_url, href) 
    } else { 
        format!("{}/{}", base_url, href) 
    };
    
    xml.push_str("  <D:response>\n");
    xml.push_str(&format!("    <D:href>{}</D:href>\n", full_href));
    xml.push_str("    <D:propstat>\n      <D:prop>\n");
    
    if path.is_dir() {
        xml.push_str("        <D:resourcetype><D:collection/></D:resourcetype>\n");
    } else {
        xml.push_str("        <D:resourcetype/>\n");
    }
    
    let metadata = path.metadata().map_err(|e| format!("metadata: {}", e))?;
    
    if let Ok(modified) = metadata.modified() {
        xml.push_str(&format!("        <D:getlastmodified>{}</D:getlastmodified>\n", format_http_date(modified)));
        xml.push_str(&format!("        <D:creationdate>{}</D:creationdate>\n", format_iso_date(modified)));
    }
    
    if path.is_file() {
        xml.push_str(&format!("        <D:getcontentlength>{}</D:getcontentlength>\n", metadata.len()));
        let ct = match path.extension().and_then(|e| e.to_str()) {
            Some("mp4") => "video/mp4", Some("mkv") => "video/x-matroska", Some("jpg") => "image/jpeg",
            Some("pdf") => "application/pdf", _ => "application/octet-stream",
        };
        xml.push_str(&format!("        <D:getcontenttype>{}</D:getcontenttype>\n", ct));
        
        if let Ok(duration) = metadata.modified().unwrap().duration_since(UNIX_EPOCH) {
            xml.push_str(&format!("        <D:getetag>\"{:x}-{:x}\"</D:getetag>\n", metadata.len(), duration.as_secs()));
        }
    } else {
        xml.push_str("        <D:getcontenttype>httpd/unix-directory</D:getcontenttype>\n");
    }
    
    xml.push_str("        <D:supportedlock><D:lockentry><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock>\n");
    xml.push_str("        <D:lockdiscovery/>\n");
    xml.push_str("      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n");
    Ok(())
}

pub fn handle_mkcol(request: &Request, physical_path: &Path, user: &str, remote_addr: &str, url: &str, logger: &Logger) -> Response<Cursor<Vec<u8>>> {
    if physical_path.exists() {
        logger.access(remote_addr, user, "MKCOL", url, 405, 0);
        return empty_response(405);
    }
    match fs::create_dir(physical_path) {
        Ok(_) => { logger.access(remote_addr, user, "MKCOL", url, 201, 0); empty_response(201) }
        Err(e) => { logger.error(&format!("MKCOL error: {}", e)); logger.access(remote_addr, user, "MKCOL", url, 409, 0); empty_response(409) }
    }
}

pub fn handle_copy(request: &Request, physical_path: &Path, user: &str, remote_addr: &str, url: &str, logger: &Logger, root_path: &Path) -> Response<Cursor<Vec<u8>>> {
    if !physical_path.exists() { return empty_response(404); }
    let dest = match get_destination_header(request, root_path, logger) {
        Some(d) => d, None => return empty_response(400),
    };
    let overwrite = request.headers().iter().find(|h| h.field.as_str().to_ascii_lowercase() == "overwrite").map(|h| h.value.as_str() != "F").unwrap_or(true);
    
    if dest.exists() && !overwrite { return empty_response(412); }
    if dest.exists() && dest.is_dir() { return empty_response(409); }
    
    if let Some(p) = dest.parent() { if !p.exists() { let _ = fs::create_dir_all(p); } }
    
    let res = if physical_path.is_dir() { copy_dir_all(physical_path, &dest) } else { fs::copy(physical_path, &dest).map(|_| ()) };
    
    match res {
        Ok(_) => { logger.access(remote_addr, user, "COPY", url, 201, 0); empty_response(201) }
        Err(e) => { logger.error(&format!("Copy error: {}", e)); empty_response(500) }
    }
}

pub fn handle_move(request: &Request, physical_path: &Path, user: &str, remote_addr: &str, url: &str, logger: &Logger, root_path: &Path) -> Response<Cursor<Vec<u8>>> {
    if !physical_path.exists() { return empty_response(404); }
    let dest = match get_destination_header(request, root_path, logger) {
        Some(d) => d, None => return empty_response(400),
    };
    let overwrite = request.headers().iter().find(|h| h.field.as_str().to_ascii_lowercase() == "overwrite").map(|h| h.value.as_str() != "F").unwrap_or(true);
    
    if dest.exists() && !overwrite { return empty_response(412); }
    if dest.exists() { let _ = if dest.is_dir() { fs::remove_dir_all(&dest) } else { fs::remove_file(&dest) }; }
    if let Some(p) = dest.parent() { if !p.exists() { let _ = fs::create_dir_all(p); } }
    
    match fs::rename(physical_path, &dest) {
        Ok(_) => { logger.access(remote_addr, user, "MOVE", url, 201, 0); empty_response(201) }
        Err(e) => { logger.error(&format!("Move error: {}", e)); empty_response(500) }
    }
}

fn get_destination_header(request: &Request, root_path: &Path, logger: &Logger) -> Option<PathBuf> {
    let h = request.headers().iter().find(|h| h.field.as_str().to_ascii_lowercase() == "destination")?;
    let val = h.value.as_str();
    let uri = val.split("://").nth(1)?;
    let p_start = uri.find('/')?;
    crate::server::build_physical_path(&uri[p_start..], root_path)
}

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    if !dst.exists() { fs::create_dir_all(dst)?; }
    for entry in fs::read_dir(src)? {
        let e = entry?;
        let src_p = e.path();
        let dst_p = dst.join(e.file_name());
        if e.file_type()?.is_dir() { copy_dir_all(&src_p, &dst_p)?; } else { fs::copy(&src_p, &dst_p)?; }
    }
    Ok(())
}

pub fn handle_lock(request: &Request, physical_path: &Path, user: &str, remote_addr: &str, url: &str, logger: &Logger, lock_mgr: Arc<LockManager>) -> Response<Cursor<Vec<u8>>> {
    if !physical_path.exists() {
        logger.access(remote_addr, user, "LOCK", url, 404, 0);
        return empty_response(404);
    }
    
    let token = lock_mgr.create_lock(physical_path, user);
    
    let xml = format!(r#"<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:">
  <D:lockdiscovery>
    <D:activelock>
      <D:locktype><D:write/></D:locktype>
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:depth>0</D:depth>
      <D:owner>{}</D:owner>
      <D:timeout>Second-3600</D:timeout>
      <D:locktoken><D:href>{}</D:href></D:locktoken>
      <D:lockroot><D:href>{}</D:href></D:lockroot>
    </D:activelock>
  </D:lockdiscovery>
</D:prop>"#, user, token, url);

    logger.access(remote_addr, user, "LOCK", url, 200, xml.len() as u64);
    let mut resp = Response::from_string(xml).with_status_code(StatusCode(200));
    resp.add_header(Header::from_bytes("Content-Type", "application/xml; charset=utf-8").unwrap());
    resp.add_header(Header::from_bytes("Lock-Token", token.as_str()).unwrap());
    resp
}

pub fn handle_unlock(request: &Request, physical_path: &Path, user: &str, remote_addr: &str, url: &str, logger: &Logger, lock_mgr: Arc<LockManager>) -> Response<Cursor<Vec<u8>>> {
    if !physical_path.exists() { return empty_response(404); }
    
    let token = request.headers().iter()
        .find(|h| h.field.as_str().to_ascii_lowercase() == "lock-token")
        .map(|h| h.value.as_str());
        
    if let Some(t) = token {
        if lock_mgr.remove_lock(t) {
            logger.access(remote_addr, user, "UNLOCK", url, 204, 0);
            return empty_response(204);
        }
    }
    
    logger.debug("Unlock request with invalid/missing token");
    empty_response(204)
}

pub fn handle_options() -> Response<Cursor<Vec<u8>>> {
    let mut r = empty_response(200);
    r.add_header(Header::from_bytes("DAV", "1,2").unwrap());
    r.add_header(Header::from_bytes("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL, COPY, MOVE, LOCK, UNLOCK").unwrap());
    r.add_header(Header::from_bytes("Accept-Ranges", "bytes").unwrap());
    r
}

