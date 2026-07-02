use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand, ValueEnum};
use nivrit_crypto::{
    decapsulate_project_key_hybrid, decrypt_value, derive_key, encapsulate_project_key_hybrid,
    encrypt_value, EncapsulatedProjectKey, HybridUserKeyPair,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

mod scan;

#[derive(Parser)]
#[command(name = "niv")]
#[command(about = "Nivrit CLI for secret management")]
struct Cli {
    #[arg(short, long, default_value = "http://localhost:4000")]
    server: String,

    #[arg(long, global = true, default_value = "plain", value_enum)]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, PartialEq, ValueEnum)]
enum OutputFormat {
    Plain,
    Json,
}

fn print_output<T: Serialize>(format: OutputFormat, plain: &str, value: &T) {
    match format {
        OutputFormat::Plain => println!("{}", plain),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(value).unwrap()),
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Register a new account
    Register {
        #[arg(short, long)]
        email: String,
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Log in with password or a personal access token
    Login {
        #[arg(short, long)]
        email: Option<String>,
        #[arg(short, long)]
        password: Option<String>,
        /// Authenticate with a personal access token instead of a password
        #[arg(short, long)]
        pat: Option<String>,
    },
    /// Show the current user and session status
    Whoami,
    /// Create an organization
    CreateOrg {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        slug: String,
    },
    /// Create a project
    CreateProject {
        #[arg(short, long)]
        org_id: String,
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        slug: String,
    },
    /// Create an environment
    CreateEnvironment {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        slug: String,
    },
    /// List folders in an environment
    ListFolders {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        environment_id: String,
    },
    /// Create a folder
    CreateFolder {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        environment_id: String,
        #[arg(short, long)]
        name: String,
        #[arg(long)]
        path: String,
    },
    /// Delete a folder (and any secrets directly under it)
    DeleteFolder {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        folder_id: String,
    },
    /// List secret imports for an environment
    ListImports {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        environment_id: String,
    },
    /// Import another environment's secrets into this one
    CreateImport {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        environment_id: String,
        #[arg(short, long)]
        source_environment_id: String,
        #[arg(long, default_value_t = 0)]
        position: i32,
    },
    /// Delete a secret import
    DeleteImport {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        import_id: String,
    },
    /// List tags in a project
    ListTags {
        #[arg(short, long)]
        project_id: String,
    },
    /// Create a tag
    CreateTag {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        name: String,
        #[arg(short, long, default_value = "#888888")]
        color: String,
    },
    /// Delete a tag
    DeleteTag {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        tag_id: String,
    },
    /// List tags on a secret
    SecretTags {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        environment_id: String,
        #[arg(short, long)]
        key: String,
    },
    /// Attach a tag to a secret
    TagSecret {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        environment_id: String,
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        tag_id: String,
    },
    /// Detach a tag from a secret
    UntagSecret {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        environment_id: String,
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        tag_id: String,
    },
    /// Set a secret
    Set {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        environment_id: String,
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        value: String,
    },
    /// Get a secret
    Get {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        environment_id: String,
        #[arg(short, long)]
        key: String,
    },
    /// List secrets in an environment
    ListSecrets {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        environment_id: String,
    },
    /// Delete a secret
    DeleteSecret {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        environment_id: String,
        #[arg(short, long)]
        key: String,
    },
    /// List a secret's version history (decrypted)
    Versions {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        environment_id: String,
        #[arg(short, long)]
        key: String,
    },
    /// Restore a secret to a prior version (writes it forward as a new version)
    Restore {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        environment_id: String,
        #[arg(short, long)]
        key: String,
        #[arg(short = 'V', long)]
        version: i32,
    },
    /// List projects in an organization
    ListProjects {
        #[arg(short, long)]
        org_id: String,
    },
    /// List environments in a project
    ListEnvironments {
        #[arg(short, long)]
        project_id: String,
    },
    /// Export decrypted secrets as shell environment variables
    Env {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        environment_id: String,
    },
    /// Run a command with decrypted secrets injected as environment variables
    Run {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        environment_id: String,
        /// Command and args to run, e.g. `niv run -p .. -e .. -- node app.js`
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Scan a path for hard-coded secrets (exits non-zero if any are found)
    Scan {
        /// Path to scan (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Manage personal access tokens
    Pat {
        #[command(subcommand)]
        subcommand: PatCommands,
    },
    /// Invite a user to a project by sharing the project key
    Invite {
        #[arg(short, long)]
        project_id: String,
        #[arg(short, long)]
        email: String,
        #[arg(short, long, default_value = "member")]
        role: String,
    },
    /// Rotate the current user's hybrid key pair and re-encrypt project keys
    RotateKey {
        #[arg(short, long)]
        password: String,
    },
}

#[derive(Subcommand)]
enum PatCommands {
    /// Create a new personal access token
    Create {
        #[arg(short, long)]
        name: String,
        /// Token lifetime in days
        #[arg(long)]
        expires_in_days: Option<i64>,
    },
    /// List personal access tokens
    List,
    /// Revoke a personal access token by ID
    Revoke { token_id: String },
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct CliConfig {
    server_url: String,
    token: Option<String>,
    user_id: Option<String>,
    email: Option<String>,
    public_key: Option<String>,
    encrypted_private_key: Option<String>,
    private_key_nonce: Option<String>,
    private_key_algorithm: Option<String>,
    /// Base64-encoded plaintext hybrid private key, cached locally after login.
    private_key: Option<String>,
    project_keys: HashMap<String, EncryptedKey>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct EncryptedKey {
    ciphertext: String,
    nonce: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut config = load_config();
    config.server_url = cli.server.clone();

    let client = reqwest::Client::new();

    let format = cli.format;
    match cli.command {
        Commands::Register {
            email,
            password,
            name,
        } => {
            register(
                &client,
                &cli.server,
                &mut config,
                format,
                &email,
                &password,
                name,
            )
            .await?
        }
        Commands::Login {
            email,
            password,
            pat,
        } => {
            if let Some(pat) = pat {
                login_with_pat(
                    &client,
                    &cli.server,
                    &mut config,
                    format,
                    &pat,
                    password.as_deref(),
                )
                .await?
            } else {
                let email = email.ok_or_else(|| anyhow::anyhow!("--email required"))?;
                let password = password.ok_or_else(|| anyhow::anyhow!("--password required"))?;
                login(&client, &cli.server, &mut config, format, &email, &password).await?
            }
        }
        Commands::Whoami => whoami(&client, &config, format).await?,
        Commands::CreateOrg { name, slug } => {
            create_org(&client, &config, format, &name, &slug).await?
        }
        Commands::CreateProject { org_id, name, slug } => {
            create_project(&client, &mut config, format, &org_id, &name, &slug).await?
        }
        Commands::CreateEnvironment {
            project_id,
            name,
            slug,
        } => create_environment(&client, &config, format, &project_id, &name, &slug).await?,
        Commands::ListFolders {
            project_id,
            environment_id,
        } => list_folders(&client, &config, format, &project_id, &environment_id).await?,
        Commands::CreateFolder {
            project_id,
            environment_id,
            name,
            path,
        } => {
            create_folder(
                &client,
                &config,
                format,
                &project_id,
                &environment_id,
                &name,
                &path,
            )
            .await?
        }
        Commands::DeleteFolder {
            project_id,
            folder_id,
        } => delete_folder_cmd(&client, &config, format, &project_id, &folder_id).await?,
        Commands::ListImports {
            project_id,
            environment_id,
        } => list_imports(&client, &config, format, &project_id, &environment_id).await?,
        Commands::CreateImport {
            project_id,
            environment_id,
            source_environment_id,
            position,
        } => {
            create_import(
                &client,
                &config,
                format,
                &project_id,
                &environment_id,
                &source_environment_id,
                position,
            )
            .await?
        }
        Commands::DeleteImport {
            project_id,
            import_id,
        } => delete_import_cmd(&client, &config, format, &project_id, &import_id).await?,
        Commands::ListTags { project_id } => {
            list_tags(&client, &config, format, &project_id).await?
        }
        Commands::CreateTag {
            project_id,
            name,
            color,
        } => create_tag(&client, &config, format, &project_id, &name, &color).await?,
        Commands::DeleteTag { project_id, tag_id } => {
            delete_tag_cmd(&client, &config, format, &project_id, &tag_id).await?
        }
        Commands::SecretTags {
            project_id,
            environment_id,
            key,
        } => secret_tags(&client, &config, format, &project_id, &environment_id, &key).await?,
        Commands::TagSecret {
            project_id,
            environment_id,
            key,
            tag_id,
        } => {
            tag_secret(
                &client,
                &config,
                format,
                &project_id,
                &environment_id,
                &key,
                &tag_id,
            )
            .await?
        }
        Commands::UntagSecret {
            project_id,
            environment_id,
            key,
            tag_id,
        } => {
            untag_secret(
                &client,
                &config,
                format,
                &project_id,
                &environment_id,
                &key,
                &tag_id,
            )
            .await?
        }
        Commands::Set {
            project_id,
            environment_id,
            key,
            value,
        } => {
            set_secret(
                &client,
                &config,
                format,
                &project_id,
                &environment_id,
                &key,
                &value,
            )
            .await?
        }
        Commands::Get {
            project_id,
            environment_id,
            key,
        } => get_secret(&client, &config, format, &project_id, &environment_id, &key).await?,
        Commands::ListSecrets {
            project_id,
            environment_id,
        } => list_secrets(&client, &config, format, &project_id, &environment_id).await?,
        Commands::DeleteSecret {
            project_id,
            environment_id,
            key,
        } => delete_secret(&client, &config, format, &project_id, &environment_id, &key).await?,
        Commands::Versions {
            project_id,
            environment_id,
            key,
        } => secret_versions(&client, &config, format, &project_id, &environment_id, &key).await?,
        Commands::Restore {
            project_id,
            environment_id,
            key,
            version,
        } => {
            restore_secret(
                &client,
                &config,
                format,
                &project_id,
                &environment_id,
                &key,
                version,
            )
            .await?
        }
        Commands::ListProjects { org_id } => {
            list_projects(&client, &config, format, &org_id).await?
        }
        Commands::ListEnvironments { project_id } => {
            list_environments(&client, &config, format, &project_id).await?
        }
        Commands::Env {
            project_id,
            environment_id,
        } => export_env(&client, &config, format, &project_id, &environment_id).await?,
        Commands::Run {
            project_id,
            environment_id,
            command,
        } => run_command(&client, &config, &project_id, &environment_id, &command).await?,
        Commands::Scan { path } => scan_cmd(&path)?,
        Commands::Pat { subcommand } => match subcommand {
            PatCommands::Create {
                name,
                expires_in_days,
            } => create_pat(&client, &config, format, &name, expires_in_days).await?,
            PatCommands::List => list_pats(&client, &config, format).await?,
            PatCommands::Revoke { token_id } => {
                revoke_pat(&client, &config, format, &token_id).await?
            }
        },
        Commands::Invite {
            project_id,
            email,
            role,
        } => invite_member(&client, &config, format, &project_id, &email, &role).await?,
        Commands::RotateKey { password } => {
            rotate_key(&client, &mut config, format, &password).await?
        }
    }

    save_config(&config)?;
    Ok(())
}

fn config_path() -> PathBuf {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".nivrit").join("config.json")
}

fn load_config() -> CliConfig {
    let path = config_path();
    if path.exists() {
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        CliConfig::default()
    }
}

fn save_config(config: &CliConfig) -> anyhow::Result<()> {
    let path = config_path();
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path has no parent directory"))?;
    std::fs::create_dir_all(parent)?;
    std::fs::write(path, serde_json::to_string_pretty(config)?)?;
    Ok(())
}

fn encrypt_private_key(
    private_key_plaintext: &[u8],
    password: &str,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let salt = nivrit_crypto::keys::random_bytes::<16>();
    let key = derive_key(password.as_bytes(), &salt);
    let encrypted = encrypt_value(private_key_plaintext, &key)
        .map_err(|e| anyhow::anyhow!("failed to encrypt private key: {e}"))?;
    let mut combined = salt.to_vec();
    combined.extend_from_slice(&encrypted.ciphertext);
    Ok((combined, encrypted.nonce))
}

fn decrypt_private_key(
    encrypted_private_key: &[u8],
    nonce: &[u8],
    password: &str,
) -> anyhow::Result<Vec<u8>> {
    if encrypted_private_key.len() < 16 {
        anyhow::bail!("invalid encrypted private key length");
    }
    let salt = &encrypted_private_key[..16];
    let ciphertext = &encrypted_private_key[16..];
    let key = derive_key(password.as_bytes(), salt);
    decrypt_value(ciphertext, nonce, &key)
        .map_err(|e| anyhow::anyhow!("failed to decrypt private key: {e}"))
}

async fn register(
    client: &reqwest::Client,
    server: &str,
    config: &mut CliConfig,
    format: OutputFormat,
    email: &str,
    password: &str,
    name: Option<String>,
) -> anyhow::Result<()> {
    let keypair = HybridUserKeyPair::generate();
    let private_key_plaintext = keypair.serialize_private_key();
    let (encrypted_private_key, private_key_nonce) =
        encrypt_private_key(&private_key_plaintext, password)?;
    let public_key = keypair.serialize_public_key();

    let req = serde_json::json!({
        "email": email,
        "password": password,
        "name": name,
        "public_key": STANDARD.encode(&public_key),
        "encrypted_private_key": STANDARD.encode(&encrypted_private_key),
        "private_key_nonce": STANDARD.encode(&private_key_nonce),
        "private_key_algorithm": "aes256gcm-v1",
    });

    let res: serde_json::Value = client
        .post(format!("{}/register", server))
        .json(&req)
        .send()
        .await?
        .json()
        .await?;

    let token = res["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("token missing in register response"))?;
    let user = res["user"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("user missing in register response"))?;
    let user_id = user["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("user.id missing in register response"))?;
    let public_key_resp = user["public_key"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("user.public_key missing in register response"))?;

    config.token = Some(token.to_string());
    config.user_id = Some(user_id.to_string());
    config.email = Some(email.to_string());
    config.public_key = Some(public_key_resp.to_string());
    config.encrypted_private_key = Some(STANDARD.encode(&encrypted_private_key));
    config.private_key_nonce = Some(STANDARD.encode(&private_key_nonce));
    config.private_key_algorithm = Some("aes256gcm-v1".into());
    config.private_key = Some(STANDARD.encode(&private_key_plaintext));

    let recovery_code = res["recovery_code"].as_str().unwrap_or("");
    #[derive(Serialize)]
    struct RegisterOut {
        email: String,
        user_id: String,
        recovery_code: String,
    }
    print_output(
        format,
        &format!("registered {}\nrecovery code: {}", email, recovery_code),
        &RegisterOut {
            email: email.to_string(),
            user_id: user_id.to_string(),
            recovery_code: recovery_code.to_string(),
        },
    );
    Ok(())
}

async fn login(
    client: &reqwest::Client,
    server: &str,
    config: &mut CliConfig,
    format: OutputFormat,
    email: &str,
    password: &str,
) -> anyhow::Result<()> {
    let req = serde_json::json!({
        "email": email,
        "password": password,
    });

    let res: serde_json::Value = client
        .post(format!("{}/login", server))
        .json(&req)
        .send()
        .await?
        .json()
        .await?;

    finish_password_login(client, server, config, format, email, password, res).await
}

async fn finish_password_login(
    client: &reqwest::Client,
    server: &str,
    config: &mut CliConfig,
    format: OutputFormat,
    email: &str,
    password: &str,
    res: serde_json::Value,
) -> anyhow::Result<()> {
    let token = res["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("token missing in login response"))?;
    let user = res["user"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("user missing in login response"))?;
    let user_id = user["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("user.id missing in login response"))?;
    let public_key = user["public_key"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("user.public_key missing in login response"))?;
    let encrypted_private_key_b64 = user["encrypted_private_key"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("user.encrypted_private_key missing in login response"))?;
    let private_key_nonce_b64 = user["private_key_nonce"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("user.private_key_nonce missing in login response"))?;
    let private_key_algorithm = user["private_key_algorithm"]
        .as_str()
        .unwrap_or("aes256gcm-v1")
        .to_string();

    // Decrypt the user's hybrid private key from their password.
    let encrypted_private_key = STANDARD.decode(encrypted_private_key_b64)?;
    let private_key_nonce = STANDARD.decode(private_key_nonce_b64)?;
    let private_key_plaintext =
        decrypt_private_key(&encrypted_private_key, &private_key_nonce, password)?;

    recover_project_keys(client, server, config, token, &private_key_plaintext).await?;

    config.token = Some(token.to_string());
    config.user_id = Some(user_id.to_string());
    config.email = Some(email.to_string());
    config.public_key = Some(public_key.to_string());
    config.encrypted_private_key = Some(encrypted_private_key_b64.to_string());
    config.private_key_nonce = Some(private_key_nonce_b64.to_string());
    config.private_key_algorithm = Some(private_key_algorithm);
    config.private_key = Some(STANDARD.encode(&private_key_plaintext));

    print_login_output(format, email, config.project_keys.len());
    Ok(())
}

async fn recover_project_keys(
    client: &reqwest::Client,
    server: &str,
    config: &mut CliConfig,
    token: &str,
    private_key_plaintext: &[u8],
) -> anyhow::Result<()> {
    let projects_res: serde_json::Value = client
        .get(format!("{}/users/me/projects", server))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await?;
    let projects = projects_res
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected array from /users/me/projects"))?;

    config.project_keys.clear();
    for project in projects {
        let project_id = project["project_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("project_id missing in membership"))?;
        let encrypted_project_key_b64 = project["encrypted_project_key"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("encrypted_project_key missing in membership"))?;
        let encrypted_project_key_bytes = STANDARD.decode(encrypted_project_key_b64)?;
        if encrypted_project_key_bytes.is_empty() {
            // Skip projects where the key blob is empty (legacy/no-access rows).
            continue;
        }
        let encapsulated: EncapsulatedProjectKey =
            serde_json::from_slice(&encrypted_project_key_bytes)
                .map_err(|e| anyhow::anyhow!("invalid encrypted project key: {e}"))?;
        let project_key = decapsulate_project_key_hybrid(&encapsulated, private_key_plaintext)?;

        config.project_keys.insert(
            project_id.to_string(),
            EncryptedKey {
                ciphertext: STANDARD.encode(project_key),
                nonce: STANDARD.encode(&[] as &[u8]),
            },
        );
    }
    Ok(())
}

fn print_login_output(format: OutputFormat, email: &str, project_count: usize) {
    #[derive(Serialize)]
    struct LoginOut {
        email: String,
        projects: usize,
    }
    print_output(
        format,
        &format!("logged in {} ({} projects)", email, project_count),
        &LoginOut {
            email: email.to_string(),
            projects: project_count,
        },
    );
}

async fn login_with_pat(
    client: &reqwest::Client,
    server: &str,
    config: &mut CliConfig,
    format: OutputFormat,
    pat: &str,
    password: Option<&str>,
) -> anyhow::Result<()> {
    let me: serde_json::Value = client
        .get(format!("{}/users/me", server))
        .bearer_auth(pat)
        .send()
        .await?
        .json()
        .await?;

    let user_id = me["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("user.id missing in /users/me response"))?;
    let email = me["email"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("user.email missing in /users/me response"))?;
    let public_key = me["public_key"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("user.public_key missing in /users/me response"))?;
    let encrypted_private_key_b64 = me["encrypted_private_key"].as_str().ok_or_else(|| {
        anyhow::anyhow!("user.encrypted_private_key missing in /users/me response")
    })?;
    let private_key_nonce_b64 = me["private_key_nonce"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("user.private_key_nonce missing in /users/me response"))?;
    let private_key_algorithm = me["private_key_algorithm"]
        .as_str()
        .unwrap_or("aes256gcm-v1")
        .to_string();

    config.token = Some(pat.to_string());
    config.user_id = Some(user_id.to_string());
    config.email = Some(email.to_string());
    config.public_key = Some(public_key.to_string());
    config.encrypted_private_key = Some(encrypted_private_key_b64.to_string());
    config.private_key_nonce = Some(private_key_nonce_b64.to_string());
    config.private_key_algorithm = Some(private_key_algorithm);

    // If a password is provided, decrypt the private key and recover project keys.
    if let Some(password) = password {
        let encrypted_private_key = STANDARD.decode(encrypted_private_key_b64)?;
        let private_key_nonce = STANDARD.decode(private_key_nonce_b64)?;
        let private_key_plaintext =
            decrypt_private_key(&encrypted_private_key, &private_key_nonce, password)?;
        recover_project_keys(client, server, config, pat, &private_key_plaintext).await?;
        config.private_key = Some(STANDARD.encode(&private_key_plaintext));
    }

    print_login_output(format, email, config.project_keys.len());
    Ok(())
}

async fn whoami(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let token = config
        .token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;

    let me: serde_json::Value = client
        .get(format!("{}/users/me", config.server_url))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await?;
    let email = me["email"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("user.email missing"))?;
    let user_id = me["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("user.id missing"))?;

    let orgs: serde_json::Value = client
        .get(format!("{}/users/me/orgs", config.server_url))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await?;
    let projects: serde_json::Value = client
        .get(format!("{}/users/me/projects", config.server_url))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await?;

    let org_count = orgs.as_array().map(|a| a.len()).unwrap_or(0);
    let project_count = projects.as_array().map(|a| a.len()).unwrap_or(0);

    #[derive(Serialize)]
    struct WhoamiOut {
        server: String,
        email: String,
        user_id: String,
        orgs: usize,
        projects: usize,
        project_keys_loaded: usize,
    }
    print_output(
        format,
        &format!(
            "server: {}\nemail: {}\nuser id: {}\norgs: {}\nprojects: {}\nproject keys loaded: {}",
            config.server_url,
            email,
            user_id,
            org_count,
            project_count,
            config.project_keys.len()
        ),
        &WhoamiOut {
            server: config.server_url.clone(),
            email: email.to_string(),
            user_id: user_id.to_string(),
            orgs: org_count,
            projects: project_count,
            project_keys_loaded: config.project_keys.len(),
        },
    );
    Ok(())
}

async fn create_org(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    name: &str,
    slug: &str,
) -> anyhow::Result<()> {
    let req = serde_json::json!({"name": name, "slug": slug});
    let res: serde_json::Value = client
        .post(format!("{}/orgs", config.server_url))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .json(&req)
        .send()
        .await?
        .json()
        .await?;
    let id = res["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("org id missing in create org response"))?;
    let slug_resp = res["slug"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("slug missing in create org response"))?;

    #[derive(Serialize)]
    struct OrgOut {
        id: String,
        slug: String,
    }
    print_output(
        format,
        &format!("{} {}", id, slug_resp),
        &OrgOut {
            id: id.to_string(),
            slug: slug_resp.to_string(),
        },
    );
    Ok(())
}

async fn create_project(
    client: &reqwest::Client,
    config: &mut CliConfig,
    format: OutputFormat,
    org_id: &str,
    name: &str,
    slug: &str,
) -> anyhow::Result<()> {
    let project_key = nivrit_crypto::keys::random_bytes::<32>();

    // Encrypt the project key to the user's own public key so it can be
    // recovered on another device via /users/me/projects + password.
    let public_key_b64 = config
        .public_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("public key not available; log in first"))?;
    let public_key = STANDARD.decode(public_key_b64)?;
    let encapsulated = encapsulate_project_key_hybrid(&project_key, &public_key)
        .map_err(|e| anyhow::anyhow!("failed to encapsulate project key: {e}"))?;
    let encrypted_project_key_json = serde_json::to_vec(&encapsulated)
        .map_err(|e| anyhow::anyhow!("failed to serialize encrypted project key: {e}"))?;

    let req = serde_json::json!({
        "org_id": org_id,
        "name": name,
        "slug": slug,
        "encrypted_project_key": STANDARD.encode(&encrypted_project_key_json),
        "project_key_nonce": STANDARD.encode(&[] as &[u8]),
        "project_key_algorithm": nivrit_crypto::HYBRID_SUITE_ID,
    });

    let res: serde_json::Value = client
        .post(format!("{}/projects", config.server_url))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .json(&req)
        .send()
        .await?
        .json()
        .await?;

    let project_id = res["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("project id missing in create project response"))?;
    config.project_keys.insert(
        project_id.to_string(),
        EncryptedKey {
            ciphertext: STANDARD.encode(project_key),
            nonce: STANDARD.encode(&[] as &[u8]),
        },
    );

    let slug_resp = res["slug"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("slug missing in create project response"))?;

    #[derive(Serialize)]
    struct ProjectOut {
        id: String,
        slug: String,
    }
    print_output(
        format,
        &format!("{} {}", project_id, slug_resp),
        &ProjectOut {
            id: project_id.to_string(),
            slug: slug_resp.to_string(),
        },
    );
    Ok(())
}

async fn list_folders(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    environment_id: &str,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .get(format!(
            "{}/projects/{}/folders?environment_id={}",
            config.server_url, project_id, environment_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;

    let folders = res
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected array"))?;

    #[derive(Serialize)]
    struct FolderEntry {
        id: String,
        path: String,
        name: String,
    }
    let mut entries = Vec::new();
    let mut lines = Vec::new();
    for f in folders {
        let id = f["id"].as_str().unwrap_or("?");
        let path = f["path"].as_str().unwrap_or("?");
        let name = f["name"].as_str().unwrap_or("?");
        lines.push(format!("{}\t{}\t{}", id, path, name));
        entries.push(FolderEntry {
            id: id.to_string(),
            path: path.to_string(),
            name: name.to_string(),
        });
    }
    print_output(format, &lines.join("\n"), &entries);
    Ok(())
}

async fn create_folder(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    environment_id: &str,
    name: &str,
    path: &str,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .post(format!(
            "{}/projects/{}/folders",
            config.server_url, project_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .json(&serde_json::json!({
            "environment_id": environment_id,
            "name": name,
            "path": path,
        }))
        .send()
        .await?
        .json()
        .await?;
    let id = res["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("folder id missing in response"))?;
    #[derive(Serialize)]
    struct FolderOut {
        id: String,
        path: String,
    }
    print_output(
        format,
        &format!("{} {}", id, path),
        &FolderOut {
            id: id.to_string(),
            path: path.to_string(),
        },
    );
    Ok(())
}

async fn delete_folder_cmd(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    folder_id: &str,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .delete(format!(
            "{}/projects/{}/folders/{}",
            config.server_url, project_id, folder_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;
    print_output(format, &format!("deleted folder {}", folder_id), &res);
    Ok(())
}

async fn list_imports(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    environment_id: &str,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .get(format!(
            "{}/projects/{}/imports?environment_id={}",
            config.server_url, project_id, environment_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;

    let imports = res
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected array"))?;

    #[derive(Serialize)]
    struct ImportEntry {
        id: String,
        source_environment_id: String,
        position: i64,
    }
    let mut entries = Vec::new();
    let mut lines = Vec::new();
    for imp in imports {
        let id = imp["id"].as_str().unwrap_or("?");
        let src = imp["source_environment_id"].as_str().unwrap_or("?");
        let position = imp["position"].as_i64().unwrap_or(0);
        lines.push(format!("{}\t<- {}\t(pos {})", id, src, position));
        entries.push(ImportEntry {
            id: id.to_string(),
            source_environment_id: src.to_string(),
            position,
        });
    }
    print_output(format, &lines.join("\n"), &entries);
    Ok(())
}

async fn create_import(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    environment_id: &str,
    source_environment_id: &str,
    position: i32,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .post(format!(
            "{}/projects/{}/imports",
            config.server_url, project_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .json(&serde_json::json!({
            "environment_id": environment_id,
            "source_environment_id": source_environment_id,
            "position": position,
        }))
        .send()
        .await?
        .json()
        .await?;
    let id = res["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("import id missing in response"))?;
    #[derive(Serialize)]
    struct ImportOut {
        id: String,
        source_environment_id: String,
    }
    print_output(
        format,
        &format!("{} <- {}", id, source_environment_id),
        &ImportOut {
            id: id.to_string(),
            source_environment_id: source_environment_id.to_string(),
        },
    );
    Ok(())
}

async fn delete_import_cmd(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    import_id: &str,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .delete(format!(
            "{}/projects/{}/imports/{}",
            config.server_url, project_id, import_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;
    print_output(format, &format!("deleted import {}", import_id), &res);
    Ok(())
}

async fn list_tags(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .get(format!(
            "{}/projects/{}/tags",
            config.server_url, project_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;
    let tags = res
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected array"))?;
    let lines: Vec<String> = tags
        .iter()
        .map(|t| {
            format!(
                "{}\t{}\t{}",
                t["id"].as_str().unwrap_or("?"),
                t["name"].as_str().unwrap_or("?"),
                t["color"].as_str().unwrap_or("")
            )
        })
        .collect();
    print_output(format, &lines.join("\n"), &res);
    Ok(())
}

async fn create_tag(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    name: &str,
    color: &str,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .post(format!(
            "{}/projects/{}/tags",
            config.server_url, project_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .json(&serde_json::json!({"name": name, "color": color}))
        .send()
        .await?
        .json()
        .await?;
    let id = res["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("tag id missing in response"))?;
    print_output(format, &format!("{}\t{}", id, name), &res);
    Ok(())
}

async fn delete_tag_cmd(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    tag_id: &str,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .delete(format!(
            "{}/projects/{}/tags/{}",
            config.server_url, project_id, tag_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;
    print_output(format, &format!("deleted tag {}", tag_id), &res);
    Ok(())
}

async fn secret_tags(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    environment_id: &str,
    key: &str,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .get(format!(
            "{}/projects/{}/secrets/{}/tags?environment_id={}",
            config.server_url, project_id, key, environment_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;
    let tags = res
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected array"))?;
    let lines: Vec<String> = tags
        .iter()
        .map(|t| {
            format!(
                "{}\t{}",
                t["name"].as_str().unwrap_or("?"),
                t["color"].as_str().unwrap_or("")
            )
        })
        .collect();
    print_output(format, &lines.join("\n"), &res);
    Ok(())
}

async fn tag_secret(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    environment_id: &str,
    key: &str,
    tag_id: &str,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .post(format!(
            "{}/projects/{}/secrets/{}/tags",
            config.server_url, project_id, key
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .json(&serde_json::json!({"environment_id": environment_id, "tag_id": tag_id}))
        .send()
        .await?
        .json()
        .await?;
    print_output(format, &format!("tagged {} with {}", key, tag_id), &res);
    Ok(())
}

async fn untag_secret(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    environment_id: &str,
    key: &str,
    tag_id: &str,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .delete(format!(
            "{}/projects/{}/secrets/{}/tags/{}?environment_id={}",
            config.server_url, project_id, key, tag_id, environment_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;
    print_output(format, &format!("untagged {} from {}", key, tag_id), &res);
    Ok(())
}

async fn create_environment(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    name: &str,
    slug: &str,
) -> anyhow::Result<()> {
    let req = serde_json::json!({"name": name, "slug": slug});
    let res: serde_json::Value = client
        .post(format!(
            "{}/projects/{}/environments",
            config.server_url, project_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .json(&req)
        .send()
        .await?
        .json()
        .await?;
    let id = res["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("environment id missing in response"))?;
    let slug_resp = res["slug"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("slug missing in create environment response"))?;

    #[derive(Serialize)]
    struct EnvOut {
        id: String,
        slug: String,
    }
    print_output(
        format,
        &format!("{} {}", id, slug_resp),
        &EnvOut {
            id: id.to_string(),
            slug: slug_resp.to_string(),
        },
    );
    Ok(())
}

async fn set_secret(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    environment_id: &str,
    key: &str,
    value: &str,
) -> anyhow::Result<()> {
    let project_key = load_project_key(config, project_id)?;
    let encrypted = encrypt_value(value.as_bytes(), &project_key)?;

    let req = serde_json::json!({
        "environment_id": environment_id,
        "key": key,
        "encrypted_value": STANDARD.encode(&encrypted.ciphertext),
        "nonce": STANDARD.encode(&encrypted.nonce),
        "algorithm": "aes256gcm-v1",
    });

    let res: serde_json::Value = client
        .post(format!(
            "{}/projects/{}/secrets",
            config.server_url, project_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .json(&req)
        .send()
        .await?
        .json()
        .await?;
    let key_resp = res["key"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("key missing in create secret response"))?;
    let version = res["version"].as_i64().unwrap_or(0);

    #[derive(Serialize)]
    struct SecretSetOut {
        key: String,
        version: i64,
    }
    print_output(
        format,
        &format!("secret {} version {}", key_resp, version),
        &SecretSetOut {
            key: key_resp.to_string(),
            version,
        },
    );
    Ok(())
}

async fn get_secret(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    environment_id: &str,
    key: &str,
) -> anyhow::Result<()> {
    let project_key = load_project_key(config, project_id)?;

    let res: serde_json::Value = client
        .get(format!(
            "{}/projects/{}/secrets/{}?environment_id={}",
            config.server_url, project_id, key, environment_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;

    let encrypted_value = res["encrypted_value"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("encrypted_value missing in get secret response"))?;
    let nonce_value = res["nonce"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("nonce missing in get secret response"))?;
    let ciphertext = STANDARD.decode(encrypted_value)?;
    let nonce = STANDARD.decode(nonce_value)?;
    let plaintext = nivrit_crypto::decrypt_value(&ciphertext, &nonce, &project_key)?;

    let value = String::from_utf8_lossy(&plaintext).to_string();
    #[derive(Serialize)]
    struct SecretOut {
        key: String,
        value: String,
    }
    print_output(
        format,
        &format!("{}={}", key, value),
        &SecretOut {
            key: key.to_string(),
            value,
        },
    );
    Ok(())
}

async fn secret_versions(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    environment_id: &str,
    key: &str,
) -> anyhow::Result<()> {
    let project_key = load_project_key(config, project_id)?;

    let res: serde_json::Value = client
        .get(format!(
            "{}/projects/{}/secrets/{}/versions?environment_id={}",
            config.server_url, project_id, key, environment_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;

    let versions = res
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected array"))?;

    #[derive(Serialize)]
    struct VersionEntry {
        version: i64,
        value: String,
        created_at: String,
    }
    let mut entries = Vec::new();
    let mut plain_lines = Vec::new();
    for v in versions {
        let version = v["version"].as_i64().unwrap_or_default();
        let encrypted_value = v["encrypted_value"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("encrypted_value missing"))?;
        let nonce = v["nonce"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("nonce missing"))?;
        let created_at = v["created_at"].as_str().unwrap_or("").to_string();
        let ciphertext = STANDARD.decode(encrypted_value)?;
        let nonce = STANDARD.decode(nonce)?;
        let plaintext = nivrit_crypto::decrypt_value(&ciphertext, &nonce, &project_key)?;
        let value = String::from_utf8_lossy(&plaintext).to_string();
        plain_lines.push(format!("v{}\t{}\t{}={}", version, created_at, key, value));
        entries.push(VersionEntry {
            version,
            value,
            created_at,
        });
    }
    print_output(format, &plain_lines.join("\n"), &entries);
    Ok(())
}

async fn restore_secret(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    environment_id: &str,
    key: &str,
    version: i32,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .post(format!(
            "{}/projects/{}/secrets/{}/restore",
            config.server_url, project_id, key
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .json(&serde_json::json!({
            "environment_id": environment_id,
            "version": version,
        }))
        .send()
        .await?
        .json()
        .await?;

    let new_version = res["version"].as_i64().unwrap_or_default();
    #[derive(Serialize)]
    struct RestoreOut {
        key: String,
        restored_from: i32,
        new_version: i64,
    }
    print_output(
        format,
        &format!("restored {} from v{} (now v{})", key, version, new_version),
        &RestoreOut {
            key: key.to_string(),
            restored_from: version,
            new_version,
        },
    );
    Ok(())
}

async fn list_secrets(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    environment_id: &str,
) -> anyhow::Result<()> {
    let project_key = load_project_key(config, project_id)?;

    let res: serde_json::Value = client
        .get(format!(
            "{}/projects/{}/secrets?environment_id={}",
            config.server_url, project_id, environment_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;

    let secrets = res
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected array"))?;

    #[derive(Serialize)]
    struct SecretEntry {
        key: String,
        value: String,
    }
    let mut entries = Vec::new();
    let mut plain_lines = Vec::new();
    for secret in secrets {
        let key = secret["key"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("key missing"))?;
        let encrypted_value = secret["encrypted_value"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("encrypted_value missing"))?;
        let nonce = secret["nonce"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("nonce missing"))?;
        let ciphertext = STANDARD.decode(encrypted_value)?;
        let nonce = STANDARD.decode(nonce)?;
        let plaintext = nivrit_crypto::decrypt_value(&ciphertext, &nonce, &project_key)?;
        let value = String::from_utf8_lossy(&plaintext).to_string();
        plain_lines.push(format!("{}={}", key, value));
        entries.push(SecretEntry {
            key: key.to_string(),
            value,
        });
    }
    print_output(format, &plain_lines.join("\n"), &entries);
    Ok(())
}

async fn delete_secret(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    environment_id: &str,
    key: &str,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .delete(format!(
            "{}/projects/{}/secrets/{}?environment_id={}",
            config.server_url, project_id, key, environment_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;

    let deleted = res["deleted"].as_bool().unwrap_or(false);
    #[derive(Serialize)]
    struct DeleteOut {
        key: String,
        deleted: bool,
    }
    print_output(
        format,
        &format!("deleted {}: {}", key, deleted),
        &DeleteOut {
            key: key.to_string(),
            deleted,
        },
    );
    Ok(())
}

async fn list_projects(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    org_id: &str,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .get(format!("{}/orgs/{}/projects", config.server_url, org_id))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;

    let projects = res
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected array"))?;

    #[derive(Serialize)]
    struct ProjectEntry {
        id: String,
        slug: String,
        name: String,
    }
    let mut entries = Vec::new();
    let mut lines = Vec::new();
    for project in projects {
        let id = project["id"].as_str().unwrap_or("?");
        let slug = project["slug"].as_str().unwrap_or("?");
        let name = project["name"].as_str().unwrap_or("?");
        lines.push(format!("{} {} {}", id, slug, name));
        entries.push(ProjectEntry {
            id: id.to_string(),
            slug: slug.to_string(),
            name: name.to_string(),
        });
    }
    print_output(format, &lines.join("\n"), &entries);
    Ok(())
}

async fn list_environments(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .get(format!(
            "{}/projects/{}/environments",
            config.server_url, project_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;

    let environments = res
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected array"))?;

    #[derive(Serialize)]
    struct EnvironmentEntry {
        id: String,
        slug: String,
        name: String,
    }
    let mut entries = Vec::new();
    let mut lines = Vec::new();
    for env in environments {
        let id = env["id"].as_str().unwrap_or("?");
        let slug = env["slug"].as_str().unwrap_or("?");
        let name = env["name"].as_str().unwrap_or("?");
        lines.push(format!("{} {} {}", id, slug, name));
        entries.push(EnvironmentEntry {
            id: id.to_string(),
            slug: slug.to_string(),
            name: name.to_string(),
        });
    }
    print_output(format, &lines.join("\n"), &entries);
    Ok(())
}

/// Fetch + decrypt one environment's secrets (root folder) into a key→value map.
async fn fetch_env_secrets(
    client: &reqwest::Client,
    config: &CliConfig,
    project_id: &str,
    environment_id: &str,
    project_key: &[u8; 32],
) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let res: serde_json::Value = client
        .get(format!(
            "{}/projects/{}/secrets?environment_id={}",
            config.server_url, project_id, environment_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;

    let secrets = res
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected array"))?;

    let mut map = std::collections::HashMap::new();
    for secret in secrets {
        let key = secret["key"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("key missing"))?;
        let encrypted_value = secret["encrypted_value"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("encrypted_value missing"))?;
        let nonce = secret["nonce"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("nonce missing"))?;
        let ciphertext = STANDARD.decode(encrypted_value)?;
        let nonce = STANDARD.decode(nonce)?;
        let plaintext = nivrit_crypto::decrypt_value(&ciphertext, &nonce, project_key)?;
        map.insert(
            key.to_string(),
            String::from_utf8_lossy(&plaintext).to_string(),
        );
    }
    Ok(map)
}

/// Build the effective key→value map for an environment: imported scopes first
/// (low precedence, in server-defined position order), then the local scope on
/// top. All decryption happens here, client-side — the server only ever returns
/// ciphertext, so references and imports resolve without it seeing plaintext.
///
/// ponytail: one level of imports. Recurse through `source_environment_id` if
/// transitive imports (A imports B imports C) are needed.
async fn resolve_env_map(
    client: &reqwest::Client,
    config: &CliConfig,
    project_id: &str,
    environment_id: &str,
    project_key: &[u8; 32],
) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let mut map = std::collections::HashMap::new();

    let imports: serde_json::Value = client
        .get(format!(
            "{}/projects/{}/imports?environment_id={}",
            config.server_url, project_id, environment_id
        ))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;
    if let Some(arr) = imports.as_array() {
        for imp in arr {
            if let Some(src) = imp["source_environment_id"].as_str() {
                let src_map =
                    fetch_env_secrets(client, config, project_id, src, project_key).await?;
                map.extend(src_map); // imported: low precedence
            }
        }
    }

    let local = fetch_env_secrets(client, config, project_id, environment_id, project_key).await?;
    map.extend(local); // local overrides imports
    Ok(map)
}

/// Resolve `${KEY}` references against the secret set. Unknown names are left
/// literal; circular references error.
fn resolve_references(
    raw: &std::collections::HashMap<String, String>,
) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let mut cache = std::collections::HashMap::new();
    let mut out = std::collections::HashMap::new();
    for key in raw.keys() {
        let mut stack = Vec::new();
        out.insert(key.clone(), resolve_one(key, raw, &mut cache, &mut stack)?);
    }
    Ok(out)
}

fn resolve_one(
    key: &str,
    raw: &std::collections::HashMap<String, String>,
    cache: &mut std::collections::HashMap<String, String>,
    stack: &mut Vec<String>,
) -> anyhow::Result<String> {
    if let Some(v) = cache.get(key) {
        return Ok(v.clone());
    }
    if stack.iter().any(|k| k == key) {
        anyhow::bail!("circular secret reference involving ${{{}}}", key);
    }
    let template = raw.get(key).cloned().unwrap_or_default();
    stack.push(key.to_string());

    let mut result = String::new();
    let mut rest = template.as_str();
    while let Some(start) = rest.find("${") {
        result.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find('}') {
            let name = &after[..end];
            if raw.contains_key(name) {
                result.push_str(&resolve_one(name, raw, cache, stack)?);
            } else {
                result.push_str("${");
                result.push_str(name);
                result.push('}');
            }
            rest = &after[end + 1..];
        } else {
            result.push_str("${");
            rest = after;
        }
    }
    result.push_str(rest);

    stack.pop();
    cache.insert(key.to_string(), result.clone());
    Ok(result)
}

async fn export_env(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    environment_id: &str,
) -> anyhow::Result<()> {
    let project_key = load_project_key(config, project_id)?;

    let merged = resolve_env_map(client, config, project_id, environment_id, &project_key).await?;
    let resolved = resolve_references(&merged)?;

    #[derive(Serialize)]
    struct EnvEntry {
        key: String,
        value: String,
    }
    let mut keys: Vec<&String> = resolved.keys().collect();
    keys.sort();
    let mut entries = Vec::new();
    let mut lines = Vec::new();
    for key in keys {
        let value = &resolved[key];
        lines.push(format!("{}=\"{}\"", key, value.replace('"', "\\\"")));
        entries.push(EnvEntry {
            key: key.clone(),
            value: value.clone(),
        });
    }
    print_output(format, &lines.join("\n"), &entries);
    Ok(())
}

/// Run a child process with decrypted+resolved secrets injected as env vars on
/// top of the inherited environment. Exits with the child's status code.
async fn run_command(
    client: &reqwest::Client,
    config: &CliConfig,
    project_id: &str,
    environment_id: &str,
    command: &[String],
) -> anyhow::Result<()> {
    let project_key = load_project_key(config, project_id)?;
    let merged = resolve_env_map(client, config, project_id, environment_id, &project_key).await?;
    let resolved = resolve_references(&merged)?;

    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("no command given"))?;

    // Inherits parent env; secrets layered on top (override matching names).
    let status = std::process::Command::new(program)
        .args(args)
        .envs(&resolved)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run `{}`: {}", program, e))?;

    std::process::exit(status.code().unwrap_or(1));
}

/// Scan a path for hard-coded secrets. Prints findings and exits non-zero if
/// any are found, so it works as a pre-commit/CI gate.
fn scan_cmd(path: &std::path::Path) -> anyhow::Result<()> {
    let findings = scan::scan_path(path);
    if findings.is_empty() {
        eprintln!("No secrets found.");
        return Ok(());
    }
    for f in &findings {
        println!("{}:{}: {} [{}]", f.path, f.line, f.rule, f.masked);
    }
    eprintln!("\n{} potential secret(s) found.", findings.len());
    std::process::exit(1);
}

#[cfg(test)]
mod ref_tests {
    use super::resolve_references;
    use std::collections::HashMap;

    fn m(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn nested_and_unknown() {
        let r = resolve_references(&m(&[
            ("HOST", "db.internal"),
            ("PORT", "5432"),
            ("URL", "postgres://${HOST}:${PORT}/app"),
            ("KEEP", "literal ${MISSING}"),
        ]))
        .unwrap();
        assert_eq!(r["URL"], "postgres://db.internal:5432/app");
        assert_eq!(r["KEEP"], "literal ${MISSING}");
    }

    #[test]
    fn cycle_errors() {
        let err = resolve_references(&m(&[("A", "${B}"), ("B", "${A}")])).unwrap_err();
        assert!(err.to_string().contains("circular"));
    }
}

async fn create_pat(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    name: &str,
    expires_in_days: Option<i64>,
) -> anyhow::Result<()> {
    let req = serde_json::json!({
        "name": name,
        "expires_in_days": expires_in_days,
    });
    let res: serde_json::Value = client
        .post(format!("{}/auth/pat", config.server_url))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .json(&req)
        .send()
        .await?
        .json()
        .await?;

    let id = res["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("id missing"))?;
    let token = res["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("token missing"))?;
    let created = res["created_at"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("created_at missing"))?;

    #[derive(Serialize)]
    struct PatCreateOut {
        id: String,
        token: String,
        created_at: String,
    }
    print_output(
        format,
        &format!(
            "created personal access token {}\ntoken: {}\ncreated at: {}\n(store this token now; it will not be shown again)",
            id, token, created
        ),
        &PatCreateOut {
            id: id.to_string(),
            token: token.to_string(),
            created_at: created.to_string(),
        },
    );
    Ok(())
}

async fn list_pats(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .get(format!("{}/auth/pats", config.server_url))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;

    let pats = res
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected array"))?;
    if format == OutputFormat::Plain {
        println!(
            "{:<36} {:<20} {:<20} {:<20} {:<20} {:<20}",
            "id", "name", "created", "last used", "expires", "revoked"
        );
    }

    #[derive(Serialize)]
    struct PatOut {
        id: String,
        name: String,
        created_at: String,
        last_used_at: Option<String>,
        expires_at: Option<String>,
        revoked_at: Option<String>,
    }
    let mut entries = Vec::new();
    for pat in pats {
        let id = pat["id"].as_str().unwrap_or("?");
        let name = pat["name"].as_str().unwrap_or("?");
        let created = pat["created_at"].as_str().unwrap_or("?");
        let last_used = pat["last_used_at"].as_str();
        let expires = pat["expires_at"].as_str();
        let revoked = pat["revoked_at"].as_str();
        entries.push(PatOut {
            id: id.to_string(),
            name: name.to_string(),
            created_at: created.to_string(),
            last_used_at: last_used.map(|s| s.to_string()),
            expires_at: expires.map(|s| s.to_string()),
            revoked_at: revoked.map(|s| s.to_string()),
        });
    }
    if format == OutputFormat::Plain {
        for e in &entries {
            let revoked = e.revoked_at.as_deref().unwrap_or("no");
            println!(
                "{:<36} {:<20} {:<20} {:<20} {:<20} {:<20}",
                e.id,
                e.name,
                e.created_at,
                e.last_used_at.as_deref().unwrap_or("never"),
                e.expires_at.as_deref().unwrap_or("never"),
                revoked
            );
        }
    } else {
        print_output(format, "", &entries);
    }
    Ok(())
}

async fn revoke_pat(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    token_id: &str,
) -> anyhow::Result<()> {
    let res: serde_json::Value = client
        .delete(format!("{}/auth/pats/{}", config.server_url, token_id))
        .bearer_auth(config.token.as_deref().unwrap_or(""))
        .send()
        .await?
        .json()
        .await?;
    let revoked = res["revoked"].as_bool().unwrap_or(false);
    #[derive(Serialize)]
    struct RevokeOut {
        id: String,
        revoked: bool,
    }
    print_output(
        format,
        &format!("revoked {}: {}", token_id, revoked),
        &RevokeOut {
            id: token_id.to_string(),
            revoked,
        },
    );
    Ok(())
}

async fn rotate_key(
    client: &reqwest::Client,
    config: &mut CliConfig,
    format: OutputFormat,
    password: &str,
) -> anyhow::Result<()> {
    let token = config
        .token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    let encrypted_private_key = STANDARD.decode(
        config
            .encrypted_private_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("encrypted private key not available"))?,
    )?;
    let private_key_nonce = STANDARD.decode(
        config
            .private_key_nonce
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("private key nonce not available"))?,
    )?;

    // Decrypt the existing hybrid private key to verify the password.
    let _old_private_key =
        decrypt_private_key(&encrypted_private_key, &private_key_nonce, password)?;

    // Generate a new hybrid key pair and encrypt the new private key.
    let new_keypair = HybridUserKeyPair::generate();
    let new_private_key_plaintext = new_keypair.serialize_private_key();
    let (new_encrypted_private_key, new_private_key_nonce) =
        encrypt_private_key(&new_private_key_plaintext, password)?;
    let new_public_key = new_keypair.serialize_public_key();

    // Re-encrypt every project key we hold to the new public key.
    let mut rotated_project_keys = Vec::new();
    for (project_id, encrypted) in &config.project_keys {
        let project_key_bytes = STANDARD.decode(&encrypted.ciphertext)?;
        let project_key: [u8; 32] = project_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid project key length"))?;

        let new_enc = encapsulate_project_key_hybrid(&project_key, &new_public_key)?;
        let new_enc_json = serde_json::to_vec(&new_enc)?;

        rotated_project_keys.push(serde_json::json!({
            "project_id": project_id,
            "encrypted_project_key": STANDARD.encode(&new_enc_json),
            "project_key_nonce": STANDARD.encode(&[] as &[u8]),
            "project_key_algorithm": nivrit_crypto::HYBRID_SUITE_ID,
        }));
    }

    let req = serde_json::json!({
        "public_key": STANDARD.encode(&new_public_key),
        "encrypted_private_key": STANDARD.encode(&new_encrypted_private_key),
        "private_key_nonce": STANDARD.encode(&new_private_key_nonce),
        "private_key_algorithm": "aes256gcm-v1",
        "project_keys": rotated_project_keys,
    });

    let res: serde_json::Value = client
        .post(format!("{}/users/me/rotate-key", config.server_url))
        .bearer_auth(token)
        .json(&req)
        .send()
        .await?
        .json()
        .await?;

    let rotated = res["rotated"].as_bool().unwrap_or(false);
    if rotated {
        // Update local config with the new keys.
        config.public_key = Some(STANDARD.encode(&new_public_key));
        config.encrypted_private_key = Some(STANDARD.encode(&new_encrypted_private_key));
        config.private_key_nonce = Some(STANDARD.encode(&new_private_key_nonce));
        config.private_key = Some(STANDARD.encode(&new_private_key_plaintext));
    } else {
        anyhow::bail!("server did not confirm key rotation");
    }

    #[derive(Serialize)]
    struct RotateOut {
        rotated: bool,
        re_encrypted: usize,
    }
    print_output(
        format,
        &format!(
            "rotated key pair; re-encrypted {} project keys",
            rotated_project_keys.len()
        ),
        &RotateOut {
            rotated,
            re_encrypted: rotated_project_keys.len(),
        },
    );
    Ok(())
}

fn load_project_key(config: &CliConfig, project_id: &str) -> anyhow::Result<[u8; 32]> {
    let encrypted = config
        .project_keys
        .get(project_id)
        .ok_or_else(|| anyhow::anyhow!("project key not found"))?;
    let ciphertext = STANDARD.decode(&encrypted.ciphertext)?;
    ciphertext
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid project key length"))
}

async fn invite_member(
    client: &reqwest::Client,
    config: &CliConfig,
    format: OutputFormat,
    project_id: &str,
    email: &str,
    role: &str,
) -> anyhow::Result<()> {
    let token = config
        .token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;

    // 1. Look up the invitee's public key.
    let public_key_res: serde_json::Value = client
        .get(format!(
            "{}/users/public-key?email={}",
            config.server_url,
            urlencoding::encode(email)
        ))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await?;

    let public_key_b64 = public_key_res["public_key"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("public_key missing in response"))?;
    let public_key_bytes = STANDARD.decode(public_key_b64)?;

    // 2. Load the plaintext project key from local config.
    let project_key = load_project_key(config, project_id)?;

    // 3. Encapsulate the project key to the invitee's hybrid public key.
    let encapsulated = encapsulate_project_key_hybrid(&project_key, &public_key_bytes)?;

    // 4. Send the invitation.
    let req = serde_json::json!({
        "email": email,
        "role": role,
        "encrypted_project_key": encapsulated,
    });

    let res: serde_json::Value = client
        .post(format!(
            "{}/projects/{}/members",
            config.server_url, project_id
        ))
        .bearer_auth(token)
        .json(&req)
        .send()
        .await?
        .json()
        .await?;

    let user_id = res["user_id"].as_str().unwrap_or("?");
    let project_id_resp = res["project_id"].as_str().unwrap_or("?");
    let role_resp = res["role"].as_str().unwrap_or("?");

    #[derive(Serialize)]
    struct InviteOut {
        user_id: String,
        project_id: String,
        role: String,
    }
    print_output(
        format,
        &format!(
            "invited {} to project {} as {}",
            user_id, project_id_resp, role_resp
        ),
        &InviteOut {
            user_id: user_id.to_string(),
            project_id: project_id_resp.to_string(),
            role: role_resp.to_string(),
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_encrypt_decrypt_roundtrip() {
        let password = "correct-horse-battery-staple";
        let plaintext = b"hybrid-private-key-bytes";
        let (encrypted, nonce) = encrypt_private_key(plaintext, password).unwrap();
        let decrypted = decrypt_private_key(&encrypted, &nonce, password).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn private_key_decrypt_fails_with_wrong_password() {
        let password = "correct-horse-battery-staple";
        let plaintext = b"hybrid-private-key-bytes";
        let (encrypted, nonce) = encrypt_private_key(plaintext, password).unwrap();
        assert!(decrypt_private_key(&encrypted, &nonce, "wrong-password").is_err());
    }

    #[test]
    fn self_encapsulated_project_key_roundtrip() {
        let project_key = nivrit_crypto::keys::random_bytes::<32>();
        let keypair = HybridUserKeyPair::generate();
        let public_key = keypair.serialize_public_key();
        let private_key = keypair.serialize_private_key();

        let encapsulated = encapsulate_project_key_hybrid(&project_key, &public_key).unwrap();
        let json = serde_json::to_vec(&encapsulated).unwrap();
        let decoded: EncapsulatedProjectKey = serde_json::from_slice(&json).unwrap();
        let recovered = decapsulate_project_key_hybrid(&decoded, &private_key).unwrap();

        assert_eq!(project_key, recovered);
    }
}
