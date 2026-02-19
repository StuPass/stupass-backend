use anyhow::Result;
use chrono::{Datelike, NaiveDate, TimeZone, Utc};
use fake::{
    Fake,
    faker::{
        company::en::CompanyName, lorem::en::Sentence, name::en::Name,
        phone_number::en::PhoneNumber,
    },
    rand::SeedableRng,
    rand::seq::IndexedRandom,
};
use sea_orm::{ActiveModelTrait, Database, DatabaseConnection, EntityTrait, PaginatorTrait, Set};
use std::collections::HashMap;
use stupass_backend::entities::user;
use uuid::Uuid;

/// Shadow table: university name -> student count (last assigned index)
type UniversityRegistry = HashMap<String, usize>;

struct PartialUser {
    id: Uuid,
    username: String,
    email: String,
    phone: String,
    full_name: String,
    bio: Option<String>,
    date_of_birth: NaiveDate,
    school_name: String,
    reputation_score: i32,
}

/// Configuration for user seeding
pub struct UserSeedConfig {
    /// Number of users to generate (required)
    pub num_users: usize,
    /// Database connection URL (required)
    pub db_url: String,
    /// Number of universities (optional; None = auto-calculate 10% of num_users)
    pub num_uni: Option<usize>,
    /// Random seed for reproducibility (default: 0)
    pub seed: u64,
}

/// Seed the database with fake user data.
///
/// ## Arguments
/// * `config` - Configuration specifying user count, database URL, university count, and seed
///
/// ## Returns
/// The university registry mapping university names to student counts
pub async fn seed_users(config: UserSeedConfig) -> Result<UniversityRegistry> {
    let mut rng = fake::rand::rngs::StdRng::seed_from_u64(config.seed);

    // Calculate number of universities:
    // clamp to [1, num_users / 10]
    let num_universities = match config.num_uni {
        Some(n) => n.clamp(1, (config.num_users / 10).max(1)),
        None => (config.num_users / 10).max(1),
    };

    println!("Using random seed: {}", config.seed);
    println!(
        "Generating {} universities for {} users...",
        num_universities, config.num_users
    );

    // Phase 0: Generate universities (shadow table)
    let universities = generate_universities(num_universities, &mut rng);
    let university_names: Vec<String> = universities.keys().cloned().collect();
    println!("Generated universities: {:?}", university_names);

    // Phase 1: Generate partial users (without student_id, verification_status, etc.)
    let mut partial_users: Vec<PartialUser> = (0..config.num_users)
        .map(|i| generate_partial_user(i, &university_names, &mut rng))
        .collect();

    // Sort by full_name (first name then last name) for student index assignment
    partial_users.sort_by(|a, b| a.full_name.cmp(&b.full_name));

    // Phase 2: Assign university-specific fields
    let mut university_registry: UniversityRegistry = universities;
    let complete_users: Vec<user::ActiveModel> = partial_users
        .into_iter()
        .map(|partial| finalize_user(partial, &mut university_registry, &mut rng))
        .collect();

    // Insert into database
    println!("Connecting to database...");
    let db: DatabaseConnection = Database::connect(&config.db_url).await?;

    println!("Inserting {} users...", complete_users.len());

    if !complete_users.is_empty() {
        user::Entity::insert_many(complete_users).exec(&db).await?;
    }

    let count = user::Entity::find().count(&db).await?;

    // Pretty-print university registry
    println!("\n{}", "=".repeat(50));
    println!("University Registry:");
    println!("{}", "-".repeat(50));
    let mut sorted_registry: Vec<_> = university_registry.iter().collect();
    sorted_registry.sort_by_key(|(_, cnt)| std::cmp::Reverse(*cnt));
    for (name, cnt) in sorted_registry {
        println!("  {:<40} : {:>4} students", name, cnt);
    }
    println!("{}", "=".repeat(50));
    println!("Seeding complete. Total users in database: {}", count);

    Ok(university_registry)
}

fn generate_universities<R: fake::rand::Rng + Sized>(
    num: usize,
    rng: &mut R,
) -> UniversityRegistry {
    let suffixes = [
        "University",
        "Institute of Technology",
        "College",
        "Academy",
    ];
    let mut universities = HashMap::new();

    for _ in 0..num {
        let company: String = CompanyName().fake_with_rng(rng);
        let suffix = suffixes.choose(rng).unwrap();
        let name = format!("{} {}", company, suffix);
        universities.insert(name, 0);
    }

    universities
}

fn generate_partial_user<R: fake::rand::Rng + Sized>(
    index: usize,
    university_names: &[String],
    rng: &mut R,
) -> PartialUser {
    let full_name: String = Name().fake_with_rng(rng);

    let name_parts: Vec<&str> = full_name.split_whitespace().collect();
    let first_name = name_parts.first().unwrap_or(&"Unknown");
    let last_name = name_parts.last().unwrap_or(&"User");

    let username = format!(
        "{}_{}{}",
        first_name.to_lowercase(),
        last_name.to_lowercase(),
        index
    );

    let email = format!(
        "{}.{}@student.edu",
        first_name.to_lowercase(),
        last_name.to_lowercase()
    );

    let date_of_birth = NaiveDate::from_ymd_opt(
        rng.random_range(1995..2007),
        rng.random_range(1..=12),
        rng.random_range(1..=28),
    )
    .unwrap();

    let school_name = university_names.choose(rng).unwrap().clone();

    PartialUser {
        id: Uuid::new_v4(),
        username,
        email,
        phone: PhoneNumber().fake_with_rng(rng),
        full_name,
        bio: Some(Sentence(3..10).fake_with_rng(rng)),
        date_of_birth,
        school_name,
        reputation_score: rng.random_range(0..100),
    }
}

fn finalize_user<R: fake::rand::Rng + Sized>(
    partial: PartialUser,
    registry: &mut UniversityRegistry,
    rng: &mut R,
) -> user::ActiveModel {
    let now = Utc::now();

    // Assume students are admitted at age 18
    let admission_year = partial.date_of_birth.year() + 18;

    let student_index = registry.entry(partial.school_name.clone()).or_insert(0);
    *student_index += 1;
    let index = *student_index;

    let student_id = format!("{:04}{:04}", admission_year, index);

    let is_verified: bool = rng.random_range(0..2) == 1;
    let verification_status = if is_verified { "verified" } else { "pending" };

    let verified_at = if is_verified {
        let month = rng.random_range(1..13);
        let day = rng.random_range(1..29);
        Utc.with_ymd_and_hms(admission_year, month, day, 0, 0, 0)
            .single()
    } else {
        None
    };

    // Student must graduate within 4-8 years after admission
    // After that is considered expired (expelled)
    let expires_year = admission_year + rng.random_range(4..=8);
    // Assume last valid date is June 30 of the graduation year
    let student_status_expires_at = Utc.with_ymd_and_hms(expires_year, 6, 30, 0, 0, 0).single();

    user::ActiveModel {
        id: Set(partial.id),
        username: Set(partial.username),
        email: Set(partial.email),
        phone: Set(partial.phone),
        full_name: Set(partial.full_name),
        avatar_url: Set(None),
        bio: Set(partial.bio),
        date_of_birth: Set(Some(partial.date_of_birth)),
        school_id: Set(partial.school_name),
        student_id: Set(student_id),
        reputation_score: Set(partial.reputation_score),
        verification_status: Set(verification_status.to_string()),
        verified_at: Set(verified_at),
        student_status_expires_at: Set(student_status_expires_at),
        created_at: Set(now),
        updated_at: Set(now),
        deleted_at: Set(None),
    }
}
