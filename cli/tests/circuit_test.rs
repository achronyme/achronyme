use std::io::Write;

use cli::commands::ErrorFormat;
use memory::field::PrimeId;
use tempfile::NamedTempFile;

const EF: ErrorFormat = ErrorFormat::Human;

#[path = "circuit_test/assert_message.rs"]
mod assert_message;
#[path = "circuit_test/basic.rs"]
mod basic;
#[path = "circuit_test/error_format.rs"]
mod error_format;
#[path = "circuit_test/fixtures.rs"]
mod fixtures;
#[path = "circuit_test/flags.rs"]
mod flags;
#[path = "circuit_test/input_file.rs"]
mod input_file;
#[path = "circuit_test/plonkish_json.rs"]
mod plonkish_json;
#[path = "circuit_test/witness.rs"]
mod witness;

fn fixture(name: &str) -> String {
    format!(
        "{}/test/circuit/{name}",
        env!("CARGO_MANIFEST_DIR").trim_end_matches("/cli")
    )
}

fn write_temp_source(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::with_suffix(".ach").unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}
