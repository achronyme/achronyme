use clap::Parser;
use tower_lsp::{LspService, Server};

mod capabilities;
mod document;
mod handlers;
mod server;

#[derive(Parser)]
#[command(name = "achronyme-lsp")]
#[command(about = "Language Server for Achronyme")]
struct Cli {
    /// Use stdio for communication (required)
    #[arg(long)]
    stdio: bool,

    /// Enable debug mode
    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    if !args.stdio {
        eprintln!("Error: --stdio flag is required");
        std::process::exit(1);
    }

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(|client| server::Backend::new(client, args.debug));

    Server::new(stdin, stdout, socket).serve(service).await;
}
