use tower_lsp::lsp_types::*;

/// Define the server capabilities for the Achronyme LSP
pub fn server_capabilities() -> ServerCapabilities {
    ServerCapabilities {
        // Full text sync - simplest to implement
        text_document_sync: Some(TextDocumentSyncCapability::Kind(
            TextDocumentSyncKind::FULL,
        )),

        // Hover information (function signatures, type info)
        hover_provider: Some(HoverProviderCapability::Simple(true)),

        // Go to definition
        definition_provider: Some(OneOf::Left(true)),

        // Find references
        references_provider: Some(OneOf::Left(true)),

        // Document symbols (outline)
        document_symbol_provider: Some(OneOf::Left(true)),

        // Basic completion support (to be expanded)
        completion_provider: Some(CompletionOptions {
            trigger_characters: Some(vec![".".to_string(), ":".to_string()]),
            ..Default::default()
        }),

        // Signature help (function parameter hints)
        signature_help_provider: Some(SignatureHelpOptions {
            trigger_characters: Some(vec!["(".to_string(), ",".to_string()]),
            retrigger_characters: Some(vec![",".to_string()]),
            work_done_progress_options: Default::default(),
        }),

        // Document formatting support
        document_formatting_provider: Some(OneOf::Left(true)),

        // Diagnostics are pushed via publishDiagnostics (no special capability needed)

        ..Default::default()
    }
}

