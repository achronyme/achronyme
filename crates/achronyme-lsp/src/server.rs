use dashmap::DashMap;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};

use crate::capabilities;
use crate::document::Document;
use crate::handlers;

pub struct Backend {
    client: Client,
    documents: DashMap<Url, Document>,
    debug: bool,
}

impl Backend {
    pub fn new(client: Client, debug: bool) -> Self {
        Self {
            client,
            documents: DashMap::new(),
            debug,
        }
    }

    async fn log_debug(&self, message: &str) {
        if self.debug {
            self.client
                .log_message(MessageType::INFO, format!("[DEBUG] {}", message))
                .await;
        }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        self.log_debug("Initializing Achronyme LSP server").await;

        Ok(InitializeResult {
            capabilities: capabilities::server_capabilities(),
            server_info: Some(ServerInfo {
                name: "achronyme-lsp".to_string(),
                version: Some("0.1.0".to_string()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.log_debug("Server initialized successfully").await;
        self.client
            .log_message(MessageType::INFO, "Achronyme LSP server initialized")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        self.log_debug("Shutting down server").await;
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let text = params.text_document.text.clone();

        self.log_debug(&format!("Document opened: {}", uri)).await;

        let document = Document::new(text);
        let diagnostics = handlers::diagnostics::compute_diagnostics(&document);

        self.documents.insert(uri.clone(), document);

        self.client
            .publish_diagnostics(uri, diagnostics, None)
            .await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();

        self.log_debug(&format!("Document changed: {}", uri)).await;

        if let Some(mut doc) = self.documents.get_mut(&uri) {
            // Apply changes (for full sync, we just replace the entire text)
            for change in params.content_changes {
                doc.update_text(change.text);
            }

            let diagnostics = handlers::diagnostics::compute_diagnostics(&doc);

            drop(doc); // Release the lock before async call

            self.client
                .publish_diagnostics(uri, diagnostics, None)
                .await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        self.log_debug(&format!("Document closed: {}", uri)).await;
        self.documents.remove(&uri);
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        self.log_debug(&format!("Hover request at {:?}", position))
            .await;

        if let Some(doc) = self.documents.get(uri) {
            Ok(handlers::hover::get_hover(&doc, position))
        } else {
            Ok(None)
        }
    }

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        self.log_debug(&format!("Go to definition at {:?}", position))
            .await;

        if let Some(doc) = self.documents.get(uri) {
            Ok(handlers::definition::get_definition(
                &doc,
                position,
                uri.clone(),
            ))
        } else {
            Ok(None)
        }
    }

    async fn references(&self, params: ReferenceParams) -> Result<Option<Vec<Location>>> {
        let uri = &params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;

        self.log_debug(&format!("Find references at {:?}", position))
            .await;

        if let Some(doc) = self.documents.get(uri) {
            Ok(handlers::references::find_references(
                &doc,
                position,
                uri.clone(),
            ))
        } else {
            Ok(None)
        }
    }

    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> Result<Option<DocumentSymbolResponse>> {
        let uri = &params.text_document.uri;

        self.log_debug(&format!("Document symbols for: {}", uri))
            .await;

        if let Some(doc) = self.documents.get(uri) {
            Ok(handlers::symbols::get_document_symbols(&doc))
        } else {
            Ok(None)
        }
    }

    async fn completion(
        &self,
        params: CompletionParams,
    ) -> Result<Option<CompletionResponse>> {
        let uri = &params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;

        self.log_debug(&format!("Completion request at {:?}", position))
            .await;

        if let Some(doc) = self.documents.get(uri) {
            let items = handlers::completion::get_completions(&doc, position);
            Ok(Some(CompletionResponse::Array(items)))
        } else {
            Ok(None)
        }
    }

    async fn formatting(
        &self,
        params: DocumentFormattingParams,
    ) -> Result<Option<Vec<TextEdit>>> {
        let uri = &params.text_document.uri;

        self.log_debug(&format!("Formatting request for: {}", uri))
            .await;

        if let Some(doc) = self.documents.get(uri) {
            let edits = handlers::formatting::format_document(&doc, &params.options);
            Ok(Some(edits))
        } else {
            Ok(None)
        }
    }

    async fn signature_help(
        &self,
        params: SignatureHelpParams,
    ) -> Result<Option<SignatureHelp>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        self.log_debug(&format!("Signature help request at {:?}", position))
            .await;

        if let Some(doc) = self.documents.get(uri) {
            Ok(handlers::signature_help::get_signature_help(&doc, position))
        } else {
            Ok(None)
        }
    }
}

