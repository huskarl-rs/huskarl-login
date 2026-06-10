//! Error page rendering for the login flow.
//!
//! The [`ErrorPage`] trait lets you customise the HTML shown when the login
//! middleware encounters an error (session load failure, token exchange failure,
//! etc.). [`DefaultErrorPage`] provides a minimal, self-contained page with
//! XSS-safe output.

use bytes::Bytes;
use http::StatusCode;
use huskarl::core::platform::MaybeSendSync;

/// The rendered content of an error page.
pub struct ErrorPageResponse {
    /// The `Content-Type` header value (e.g. `"text/html; charset=utf-8"`).
    pub content_type: &'static str,
    /// The response body.
    pub body: Bytes,
}

/// Renders error pages for the login middleware.
///
/// The default implementation ([`DefaultErrorPage`]) produces minimal,
/// self-contained HTML. Implement this trait to customise the look of error
/// pages served during the login flow.
pub trait ErrorPage: MaybeSendSync {
    /// Render an error page for the given HTTP status and human-readable
    /// message.
    fn render(&self, status: StatusCode, message: &str) -> ErrorPageResponse;
}

/// The built-in error page renderer.
///
/// Produces a minimal, self-contained HTML page with no external resources.
/// The `message` is HTML-entity-escaped to prevent XSS.
pub struct DefaultErrorPage;

impl ErrorPage for DefaultErrorPage {
    fn render(&self, status: StatusCode, message: &str) -> ErrorPageResponse {
        let code = status.as_u16();
        let reason = status.canonical_reason().unwrap_or("Error");
        let escaped_message = html_escape(message);

        let body = format!(
            "<!DOCTYPE html>\
            <html lang=\"en\">\
            <head>\
            <meta charset=\"utf-8\">\
            <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
            <title>{code} {reason}</title>\
            <style>\
            *{{margin:0;padding:0;box-sizing:border-box}}\
            body{{font-family:system-ui,-apple-system,sans-serif;min-height:100vh;\
            display:flex;align-items:center;justify-content:center;\
            background:#f8f9fa;color:#212529}}\
            .c{{text-align:center;padding:2rem}}\
            h1{{font-size:4rem;font-weight:700;color:#dee2e6;margin-bottom:.5rem}}\
            p{{font-size:1.125rem;color:#495057}}\
            </style>\
            </head>\
            <body>\
            <div class=\"c\">\
            <h1>{code}</h1>\
            <p>{escaped_message}</p>\
            </div>\
            </body>\
            </html>"
        );

        ErrorPageResponse {
            content_type: "text/html; charset=utf-8",
            body: Bytes::from(body),
        }
    }
}

/// Escapes `&`, `<`, `>`, `"`, and `'` for safe inclusion in HTML.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_renders_html_with_status_and_message() {
        let page = DefaultErrorPage;
        let resp = page.render(StatusCode::INTERNAL_SERVER_ERROR, "something broke");
        assert_eq!(resp.content_type, "text/html; charset=utf-8");
        let body = String::from_utf8(resp.body.to_vec()).unwrap();
        assert!(body.contains("500"));
        assert!(body.contains("something broke"));
        assert!(body.contains("<!DOCTYPE html>"));
    }

    #[test]
    fn default_escapes_html_in_message() {
        let page = DefaultErrorPage;
        let resp = page.render(StatusCode::BAD_REQUEST, "<script>alert('xss')</script>");
        let body = String::from_utf8(resp.body.to_vec()).unwrap();
        assert!(!body.contains("<script>"));
        assert!(body.contains("&lt;script&gt;"));
        assert!(body.contains("&#x27;"));
    }

    #[test]
    fn html_escape_handles_all_special_chars() {
        assert_eq!(
            html_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&#x27;f"
        );
    }

    #[test]
    fn html_escape_passes_through_plain_text() {
        assert_eq!(html_escape("hello world"), "hello world");
    }
}
