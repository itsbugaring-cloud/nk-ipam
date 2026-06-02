use regex::Regex;

use crate::{
    app_error::{AppError, AppResult},
    models::BookmarkOlt,
};

pub fn parse_bookmarks_html(html: &str) -> AppResult<Vec<BookmarkOlt>> {
    let anchor_re = Regex::new(r#"(?is)<A\s+[^>]*HREF="([^"]+)"[^>]*>(.*?)</A>"#)
        .map_err(|err| AppError::Internal(format!("regex init failed: {err}")))?;
    let ip_re = Regex::new(r#"(?i)\b((?:\d{1,3}\.){3}\d{1,3})\b"#)
        .map_err(|err| AppError::Internal(format!("regex init failed: {err}")))?;
    let tag_re = Regex::new(r#"(?is)<[^>]+>"#)
        .map_err(|err| AppError::Internal(format!("regex init failed: {err}")))?;

    let mut items = Vec::new();

    for caps in anchor_re.captures_iter(html) {
        let url = caps.get(1).map(|m| m.as_str()).unwrap_or_default().trim();
        let label_raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        let label = tag_re.replace_all(label_raw, "").trim().to_string();

        let ip_address = if let Some(ip_caps) = ip_re.captures(url) {
            ip_caps.get(1).map(|m| m.as_str().to_string())
        } else {
            // Fallback: try to find IP in the label text
            ip_re.captures(&label).and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        };

        let Some(ip_address) = ip_address else {
            continue;
        };
        let name = if label.is_empty() {
            format!("OLT-{ip_address}")
        } else {
            label
        };

        items.push(BookmarkOlt {
            name,
            ip_address,
            source_url: url.to_string(),
        });
    }

    if items.is_empty() {
        return Err(AppError::BadRequest(
            "no OLT records found in bookmarks.html".to_string(),
        ));
    }

    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::parse_bookmarks_html;

    #[test]
    fn extracts_olt_name_and_ip_from_bookmarks() {
        let html = r#"
        <DL><p>
          <DT><A HREF="http://10.10.10.2/">OLT-Cikarang</A>
          <DT><A HREF="https://172.16.1.20/login">OLT-Bekasi</A>
        </DL><p>
        "#;

        let parsed = parse_bookmarks_html(html).expect("parser should extract records");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "OLT-Cikarang");
        assert_eq!(parsed[0].ip_address, "10.10.10.2");
        assert_eq!(parsed[1].ip_address, "172.16.1.20");
    }

    #[test]
    fn extracts_ip_from_label_when_url_has_no_ip() {
        let html = r#"
        <DL><p>
          <DT><A HREF="https://management.local/device">192.168.5.254 - OLT Guruh</A>
          <DT><A HREF="http://10.10.10.2/">OLT-Cikarang</A>
          <DT><A HREF="https://noc.internal/panel">172.16.0.1 - OLT Sragen</A>
        </DL><p>
        "#;

        let parsed = parse_bookmarks_html(html).expect("parser should extract records");
        assert_eq!(parsed.len(), 3);
        // First entry: IP from label text (fallback)
        assert_eq!(parsed[0].name, "192.168.5.254 - OLT Guruh");
        assert_eq!(parsed[0].ip_address, "192.168.5.254");
        assert_eq!(parsed[0].source_url, "https://management.local/device");
        // Second entry: IP from URL (existing behavior)
        assert_eq!(parsed[1].name, "OLT-Cikarang");
        assert_eq!(parsed[1].ip_address, "10.10.10.2");
        // Third entry: IP from label text (fallback)
        assert_eq!(parsed[2].name, "172.16.0.1 - OLT Sragen");
        assert_eq!(parsed[2].ip_address, "172.16.0.1");
    }
}
