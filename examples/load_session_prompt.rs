//! Example: Load an existing session by ID and send a prompt.
//!
//! Usage:
//! ```
//! cargo run --example load_session_prompt -- <SESSION_ID> [PROMPT]
//! ```
//!
//! If PROMPT is omitted, a default prompt is used.
//!
//! You can find session IDs by running the `direct_agent_test` example
//! or by listing sessions with `list_sessions`.

use std::rc::Rc;
use std::sync::Arc;

use agent_client_protocol::{
    Agent, AgentSideConnection, AuthMethodId, AuthenticateRequest, Client, ClientCapabilities,
    ClientSideConnection, Error, Implementation, InitializeRequest, ListSessionsRequest,
    LoadSessionRequest, PromptRequest, ProtocolVersion, RequestPermissionRequest,
    RequestPermissionResponse, SessionId, SessionNotification,
};
use codex_acp::CodexAgent;
use codex_core::config::{Config, ConfigOverrides};
use tokio::task::LocalSet;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

/// A stub client that receives notifications from the agent.
struct StubClient;

#[async_trait::async_trait(?Send)]
impl Client for StubClient {
    async fn request_permission(
        &self,
        _args: RequestPermissionRequest,
    ) -> Result<RequestPermissionResponse, Error> {
        println!("  [StubClient] Permission requested - auto-cancelling");
        Err(Error::request_cancelled())
    }

    async fn session_notification(&self, args: SessionNotification) -> Result<(), Error> {
        println!("  [Notification] {:?}", args.update);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("codex_acp=info".parse()?)
                .add_directive("codex_core=warn".parse()?),
        )
        .init();

    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <SESSION_ID> [PROMPT]", args[0]);
        eprintln!();
        eprintln!("Example:");
        eprintln!("  cargo run --example load_session_prompt -- abc123 \"What files are here?\"");
        std::process::exit(1);
    }

    let session_id_str = args[1].clone();
    let prompt_text = if args.len() >= 3 {
        args[2..].join(" ")
    } else {
        "Hello! Summarize what happened in this session so far.".to_string()
    };

    println!("=== Load Session & Prompt Example ===");
    println!("  Session ID: {}", session_id_str);
    println!("  Prompt: {}", prompt_text);

    // Load configuration
    let config =
        Config::load_with_cli_overrides_and_harness_overrides(vec![], ConfigOverrides::default())
            .await?;

    let local_set = LocalSet::new();
    local_set
        .run_until(async move { run_load_and_prompt(config, session_id_str, prompt_text).await })
        .await?;

    Ok(())
}

async fn run_load_and_prompt(
    config: Config,
    session_id_str: String,
    prompt_text: String,
) -> anyhow::Result<()> {
    // --- Set up ACP connection ---
    let (agent_read, client_write) = tokio::io::duplex(64 * 1024);
    let (client_read, agent_write) = tokio::io::duplex(64 * 1024);

    let agent = Rc::new(CodexAgent::new(config.clone()));

    let (acp_client, agent_io_task) = AgentSideConnection::new(
        agent.clone(),
        agent_write.compat_write(),
        agent_read.compat(),
        |fut| {
            tokio::task::spawn_local(fut);
        },
    );

    codex_acp::ACP_CLIENT
        .set(Arc::new(acp_client))
        .map_err(|_| anyhow::anyhow!("Failed to set ACP_CLIENT"))?;

    let stub_client = Rc::new(StubClient);
    let (client_conn, client_io_task) = ClientSideConnection::new(
        stub_client,
        client_write.compat_write(),
        client_read.compat(),
        |fut| {
            tokio::task::spawn_local(fut);
        },
    );

    let agent_handle = tokio::task::spawn_local(async move {
        if let Err(e) = agent_io_task.await {
            eprintln!("Agent I/O error: {:?}", e);
        }
    });
    let client_handle = tokio::task::spawn_local(async move {
        if let Err(e) = client_io_task.await {
            eprintln!("Client I/O error: {:?}", e);
        }
    });

    // --- Step 1: Initialize ---
    println!("\n--- Step 1: Initialize ---");
    let init_response = client_conn
        .initialize(
            InitializeRequest::new(ProtocolVersion::V1)
                .client_capabilities(ClientCapabilities::new())
                .client_info(Implementation::new("load-session-client", "0.1.0")),
        )
        .await?;
    println!("  Agent initialized: {:?}", init_response.agent_info);

    // --- Step 2: Authenticate ---
    println!("\n--- Step 2: Authenticate ---");
    let auth_method = if std::env::var("CODEX_API_KEY").is_ok() {
        println!("  Using CODEX_API_KEY");
        AuthMethodId::new("codex-api-key")
    } else if std::env::var("OPENAI_API_KEY").is_ok() {
        println!("  Using OPENAI_API_KEY");
        AuthMethodId::new("openai-api-key")
    } else {
        println!("  Using ChatGPT login (default)");
        AuthMethodId::new("chatgpt")
    };

    match client_conn
        .authenticate(AuthenticateRequest::new(auth_method))
        .await
    {
        Ok(_) => println!("  Authentication successful!"),
        Err(e) => {
            println!("  Authentication failed: {:?}", e);
            println!("  Continuing anyway...");
        }
    }

    // --- Step 3: Find Session and Get its CWD ---
    println!("\n--- Step 3: Find Session ---");
    let session_id = SessionId::new(session_id_str.clone());

    // List sessions to find the one with matching ID and get its cwd
    let list_response = client_conn
        .list_sessions(ListSessionsRequest::new())
        .await?;

    let session_info = list_response
        .sessions
        .iter()
        .find(|s| s.session_id.0.as_ref() == session_id_str);

    let cwd = match session_info {
        Some(info) => {
            println!("  Found session: {:?}", info.title);
            println!("  Session CWD: {:?}", info.cwd);
            info.cwd.clone()
        }
        None => {
            eprintln!("  Session '{}' not found in session list!", session_id_str);
            eprintln!("  Available sessions:");
            for s in list_response.sessions.iter().take(10) {
                eprintln!("    - {} ({:?})", s.session_id, s.title);
            }
            agent_handle.abort();
            client_handle.abort();
            return Err(anyhow::anyhow!("Session not found"));
        }
    };

    // --- Step 4: Load Session ---
    println!("\n--- Step 4: Load Session ---");
    let load_request = LoadSessionRequest::new(session_id.clone(), cwd);
    match client_conn.load_session(load_request).await {
        Ok(load_response) => {
            println!("  Session loaded successfully!");
            if let Some(modes) = &load_response.modes {
                println!("  - Current mode: {:?}", modes.current_mode_id);
            }
            if let Some(models) = &load_response.models {
                println!("  - Current model: {:?}", models.current_model_id);
            }
        }
        Err(e) => {
            eprintln!("  Failed to load session '{}': {:?}", session_id_str, e);
            agent_handle.abort();
            client_handle.abort();
            return Err(anyhow::anyhow!("load_session failed"));
        }
    }

    // --- Step 5: Send Prompt ---
    println!("\n--- Step 5: Send Prompt ---");
    println!("  Prompt: \"{}\"", prompt_text);

    let prompt_request = PromptRequest::new(session_id.clone(), vec![prompt_text.into()]);

    match client_conn.prompt(prompt_request).await {
        Ok(prompt_response) => {
            println!("  Prompt completed!");
            println!("  - Stop reason: {:?}", prompt_response.stop_reason);
        }
        Err(e) => {
            println!("  Prompt failed: {:?}", e);
        }
    }

    println!("\n=== Done ===");

    agent_handle.abort();
    client_handle.abort();

    Ok(())
}
