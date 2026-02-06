//! Example demonstrating direct usage of CodexAgent's methods.
//!
//! This example shows how to directly call CodexAgent's core methods:
//! - initialize: Initialize the agent with client capabilities
//! - authenticate: Authenticate using API key or ChatGPT login
//! - new_session: Create a new coding session
//! - load_session: Load an existing session
//! - list_sessions: List all available sessions
//! - prompt: Send a prompt to the agent
//!
//! Run with:
//! ```
//! CODEX_API_KEY=your_key cargo run --example direct_agent_test
//! ```
//! Or:
//! ```
//! OPENAI_API_KEY=your_key cargo run --example direct_agent_test
//! ```

use std::rc::Rc;
use std::sync::Arc;

use agent_client_protocol::{
    Agent, AgentSideConnection, AuthMethodId, AuthenticateRequest, Client, ClientCapabilities,
    ClientSideConnection, Error, Implementation, InitializeRequest, ListSessionsRequest,
    LoadSessionRequest, NewSessionRequest, PromptRequest, ProtocolVersion,
    RequestPermissionRequest, RequestPermissionResponse, SessionNotification,
};
use codex_acp::CodexAgent;
use codex_core::config::{Config, ConfigOverrides};
use tokio::task::LocalSet;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

/// A stub client that receives notifications from the agent
struct StubClient;

#[async_trait::async_trait(?Send)]
impl Client for StubClient {
    async fn request_permission(
        &self,
        _args: RequestPermissionRequest,
    ) -> Result<RequestPermissionResponse, Error> {
        // Auto-approve all permission requests for testing
        println!("  [StubClient] Permission requested - auto-approving");
        Err(Error::request_cancelled())
    }

    async fn session_notification(&self, args: SessionNotification) -> Result<(), Error> {
        // Print notifications for visibility
        println!("  [StubClient] Notification: {:?}", args.update);
        Ok(())
    }
}

/// A simple example that demonstrates the CodexAgent workflow
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing for logging
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("codex_acp=info".parse()?)
                .add_directive("codex_core=warn".parse()?),
        )
        .init();

    println!("=== CodexAgent Direct Test Example ===\n");

    // Load configuration
    let config =
        Config::load_with_cli_overrides_and_harness_overrides(vec![], ConfigOverrides::default())
            .await?;

    println!("Configuration loaded successfully");
    println!("  - Codex home: {:?}", config.codex_home);
    println!("  - Working directory: {:?}", config.cwd);
    println!("  - Model provider: {}", config.model_provider_id);

    // Run in a LocalSet since CodexAgent uses !Send types internally
    let local_set = LocalSet::new();
    local_set
        .run_until(async move { run_agent_tests(config).await })
        .await?;

    Ok(())
}

async fn run_agent_tests(config: Config) -> anyhow::Result<()> {
    // Create bidirectional pipes for ACP communication
    let (agent_read, client_write) = tokio::io::duplex(64 * 1024);
    let (client_read, agent_write) = tokio::io::duplex(64 * 1024);

    // Step 1: Create the CodexAgent
    println!("\n--- Step 1: Create CodexAgent ---");
    let agent = Rc::new(CodexAgent::new(config.clone()));
    println!("CodexAgent created successfully");

    // Set up the agent-side ACP connection
    let (acp_client, agent_io_task) = AgentSideConnection::new(
        agent.clone(),
        agent_write.compat_write(),
        agent_read.compat(),
        |fut| {
            tokio::task::spawn_local(fut);
        },
    );

    // Store the ACP client globally (required for session operations)
    codex_acp::ACP_CLIENT
        .set(Arc::new(acp_client))
        .map_err(|_| anyhow::anyhow!("Failed to set ACP_CLIENT"))?;

    // Set up the client-side ACP connection
    let stub_client = Rc::new(StubClient);
    let (client_conn, client_io_task) = ClientSideConnection::new(
        stub_client,
        client_write.compat_write(),
        client_read.compat(),
        |fut| {
            tokio::task::spawn_local(fut);
        },
    );

    // Spawn the I/O tasks
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

    // Now we can use client_conn to interact with the agent through ACP protocol

    // Step 2: Initialize the agent
    println!("\n--- Step 2: Initialize ---");
    let init_request = InitializeRequest::new(ProtocolVersion::V1)
        .client_capabilities(ClientCapabilities::new())
        .client_info(Implementation::new("direct-test-client", "0.1.0"));

    let init_response = client_conn.initialize(init_request).await?;
    println!("  Agent initialized successfully");
    println!("  - Agent info: {:?}", init_response.agent_info);
    println!(
        "  - Auth methods: {:?}",
        init_response
            .auth_methods
            .iter()
            .map(|m| m.name.clone())
            .collect::<Vec<_>>()
    );
    println!(
        "  - Agent capabilities: load_session={:?}",
        init_response.agent_capabilities.load_session
    );

    // Step 3: Authenticate
    println!("\n--- Step 3: Authenticate ---");

    // Default to ChatGPT login; fall back to API key env vars if set.
    let auth_method = if std::env::var("CODEX_API_KEY").is_ok() {
        println!("Using CODEX_API_KEY for authentication");
        AuthMethodId::new("codex-api-key")
    } else if std::env::var("OPENAI_API_KEY").is_ok() {
        println!("Using OPENAI_API_KEY for authentication");
        AuthMethodId::new("openai-api-key")
    } else {
        println!("Using ChatGPT login for authentication (default)");
        AuthMethodId::new("chatgpt")
    };

    let auth_request = AuthenticateRequest::new(auth_method.clone());
    println!("  Authenticating with method: {:?}", auth_method);

    match client_conn.authenticate(auth_request).await {
        Ok(_) => println!("  Authentication successful!"),
        Err(e) => {
            println!("  Authentication failed: {:?}", e);
            println!("  Continuing anyway to demonstrate the API...");
        }
    }

    // Step 4: List existing sessions
    println!("\n--- Step 4: List Sessions ---");
    let list_request = ListSessionsRequest::new();

    match client_conn.list_sessions(list_request).await {
        Ok(list_response) => {
            println!("  Found {} sessions", list_response.sessions.len());
            for (i, session) in list_response.sessions.iter().take(5).enumerate() {
                println!(
                    "    {}. ID: {}, Title: {:?}, CWD: {:?}",
                    i + 1,
                    session.session_id,
                    session.title,
                    session.cwd
                );
            }
            if list_response.sessions.len() > 5 {
                println!("    ... and {} more", list_response.sessions.len() - 5);
            }
        }
        Err(e) => {
            println!("  Failed to list sessions: {:?}", e);
        }
    }

    // Step 5: Create a new session
    println!("\n--- Step 5: New Session ---");
    let cwd = std::env::current_dir()?;
    let new_session_request = NewSessionRequest::new(cwd.clone());
    println!("  Creating session with cwd: {:?}", cwd);

    let new_session_response = match client_conn.new_session(new_session_request).await {
        Ok(response) => {
            println!("  Session created successfully!");
            println!("  - Session ID: {}", response.session_id);
            if let Some(modes) = &response.modes {
                println!(
                    "  - Available modes: {:?}",
                    modes
                        .available_modes
                        .iter()
                        .map(|m| m.name.clone())
                        .collect::<Vec<_>>()
                );
                println!("  - Current mode: {:?}", modes.current_mode_id);
            }
            if let Some(models) = &response.models {
                println!(
                    "  - Available models: {} models",
                    models.available_models.len()
                );
                println!("  - Current model: {:?}", models.current_model_id);
            }
            Some(response)
        }
        Err(e) => {
            println!("  Failed to create session: {:?}", e);
            None
        }
    };

    // Step 6: Send a prompt (if session was created)
    if let Some(session_response) = new_session_response {
        println!("\n--- Step 6: Send Prompt ---");
        let session_id = session_response.session_id;

        let prompt_request = PromptRequest::new(
            session_id.clone(),
            vec!["Say hello and tell me what you are.".into()],
        );
        println!("  Sending prompt to session: {}", session_id);

        match client_conn.prompt(prompt_request).await {
            Ok(prompt_response) => {
                println!("  Prompt completed!");
                println!("  - Stop reason: {:?}", prompt_response.stop_reason);
            }
            Err(e) => {
                println!("  Prompt failed: {:?}", e);
            }
        }

        // Step 7: Demonstrate load_session (loading the session we just created)
        println!("\n--- Step 7: Load Session ---");
        println!("  Attempting to load session: {}", session_id);

        let load_request = LoadSessionRequest::new(session_id.clone(), cwd.clone());

        match client_conn.load_session(load_request).await {
            Ok(load_response) => {
                println!("  Session loaded successfully!");
                if let Some(modes) = &load_response.modes {
                    println!("  - Current mode: {:?}", modes.current_mode_id);
                }
                if let Some(models) = &load_response.models {
                    println!("  - Current model: {:?}", models.current_model_id);
                }

                // Step 8: Send another prompt after loading the session
                println!("\n--- Step 8: Send Prompt After Load ---");
                let prompt_request = PromptRequest::new(
                    session_id.clone(),
                    vec!["What did I ask you earlier? Summarize our conversation.".into()],
                );
                println!("  Sending prompt to loaded session: {}", session_id);

                match client_conn.prompt(prompt_request).await {
                    Ok(prompt_response) => {
                        println!("  Prompt completed!");
                        println!("  - Stop reason: {:?}", prompt_response.stop_reason);
                    }
                    Err(e) => {
                        println!("  Prompt failed: {:?}", e);
                    }
                }
            }
            Err(e) => {
                println!("  Failed to load session: {:?}", e);
                println!("  (This is expected if the session was just created and not persisted)");
            }
        }
    }

    println!("\n=== Test Complete ===");

    // Clean up - abort the I/O tasks
    agent_handle.abort();
    client_handle.abort();

    Ok(())
}
