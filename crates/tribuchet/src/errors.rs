//! Rendering an error and its causes on one line ("outer: inner:
//! cause"), the shape anyhow's `{:#}` produced, for log lines and
//! wire-visible error strings.

use std::fmt::Write as _;

pub fn chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut cur = e.source();
    while let Some(cause) = cur {
        let _ = write!(out, ": {cause}");
        cur = cause.source();
    }
    out
}
