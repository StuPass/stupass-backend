use anyhow::Result;
use clap::Parser;
use dialoguer::Input;
use sea_orm::Database;
use seeder::{
    CredentialSeedConfig, UserSeedConfig, seed_auth_provider, seed_credentials, seed_users,
};
use serde_json::to_string_pretty;

/// StuPass database seeder CLI
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Number of users to generate (required)
    #[arg(short, long)]
    num_users: Option<usize>,

    /// Database connection URL (required)
    #[arg(short, long)]
    db_url: Option<String>,

    /// Number of universities (optional; default = auto-calculate 10% of num_users)
    #[arg(short = 'u', long)]
    num_uni: Option<usize>,

    /// Random seed for reproducibility (default: 0)
    #[arg(short, long, default_value = "0")]
    rng_seed: u64,

    /// Force interactive mode - prompt for all parameters including optional ones
    #[arg(short, long)]
    interactive: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let (num_users, db_url, num_uni, rng_seed) = if args.interactive {
        prompt_all(&args)?
    } else if args.num_users.is_none() || args.db_url.is_none() {
        prompt_missing(&args)?
    } else {
        (
            args.num_users.unwrap(),
            args.db_url.unwrap(),
            args.num_uni,
            args.rng_seed,
        )
    };

    let config = UserSeedConfig {
        num_users,
        db_url: db_url.clone(),
        num_uni,
        seed: rng_seed,
    };

    seed_users(config).await?;

    // Auth seeding (automatic)
    println!("\n--- Auth Seeding ---");
    let db = Database::connect(&db_url).await?;

    let provider_id = seed_auth_provider(&db).await?;
    println!("Password provider ID: {}", provider_id);

    let credentials = seed_credentials(
        &db,
        CredentialSeedConfig {
            provider_id,
            rng_seed,
        },
    )
    .await?;

    if !credentials.is_empty() {
        println!("\n--- Credentials (plaintext) ---");
        println!("{}", to_string_pretty(&credentials)?);
    }

    Ok(())
}

/// Prompt for all parameters (interactive mode)
fn prompt_all(args: &Args) -> Result<(usize, String, Option<usize>, u64)> {
    let num_users: usize = prompt_required("Number of users", args.num_users)?;

    let db_url: String = prompt_required("Database URL", args.db_url.clone())?;

    let default_uni = ((num_users as f64) * 0.1).ceil() as usize;
    let num_uni_input: String = Input::new()
        .with_prompt(format!("Number of universities [auto: {}]", default_uni))
        .allow_empty(true)
        .interact_text()?;

    let num_uni = if num_uni_input.trim().is_empty() {
        None
    } else {
        Some(num_uni_input.trim().parse()?)
    };

    let rng_seed: u64 = Input::new()
        .with_prompt("Random seed")
        .default(args.rng_seed)
        .interact_text()?;

    Ok((num_users, db_url, num_uni, rng_seed))
}

/// Prompt only for missing required parameters
fn prompt_missing(args: &Args) -> Result<(usize, String, Option<usize>, u64)> {
    let num_users = match args.num_users {
        Some(n) => n,
        None => Input::new()
            .with_prompt("Number of users")
            .interact_text()?,
    };

    let db_url = match &args.db_url {
        Some(url) => url.clone(),
        None => Input::new().with_prompt("Database URL").interact_text()?,
    };

    Ok((num_users, db_url, args.num_uni, args.rng_seed))
}

/// Prompt for a required parameter, using CLI value as default if provided
fn prompt_required<T>(prompt: &str, cli_value: Option<T>) -> Result<T>
where
    T: std::fmt::Display + std::str::FromStr + Clone,
    <T as std::str::FromStr>::Err: std::fmt::Debug + std::fmt::Display,
{
    match cli_value {
        Some(val) => {
            let input: T = Input::new()
                .with_prompt(prompt)
                .default(val)
                .interact_text()?;
            Ok(input)
        }
        None => {
            let input: T = Input::new().with_prompt(prompt).interact_text()?;
            Ok(input)
        }
    }
}
