// parse_tdx_quote guards that only TDX v4/v5 quotes are accepted.

use crate::intel_dcap::quote::{parse_quote, Quote};

/// Parse a TDX ECDSA quote (v4 or v5). Returns an error for SGX v3 quotes.
pub(crate) fn parse_tdx_quote(quote_bin: &[u8]) -> anyhow::Result<Quote> {
    let quote = parse_quote(quote_bin)?;
    match &quote {
        Quote::V4 { .. } | Quote::V5 { .. } => Ok(quote),
        Quote::V3 { .. } => anyhow::bail!("expected TDX quote (v4/v5), got SGX quote (v3)"),
    }
}
