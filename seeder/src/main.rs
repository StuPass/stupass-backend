use anyhow::Result;
use chrono::{Datelike, NaiveDate, TimeZone, Utc};
use fake::{
    Fake,
    faker::{company::en::CompanyName, lorem::en::Sentence, name::en::Name},
};
use rand::RngExt;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::IndexedRandom;
use sea_orm::{ActiveModelTrait, Database, DatabaseConnection, EntityTrait, Set};
use std::collections::HashMap;
use stupass_backend::entities::user;
use uuid::Uuid;

const NUM_USERS: usize = 10;
const NUM_UNIVERSITIES: Option<usize> = None; // None = auto-calculate (clamped to [1, 0.1 * NUM_USERS])
const DATABASE_URL: &str = "sqlite://data.db?mode=rwc";
const RANDOM_SEED: u64 = 42;

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

#[tokio::main]
async fn main() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(RANDOM_SEED);

    // Calculate number of universities
    let num_universities = match NUM_UNIVERSITIES {
        Some(n) => n.clamp(1, NUM_USERS / 10),
        None => (NUM_USERS / 10).max(1),
    };

    println!("Using random seed: {}", RANDOM_SEED);
    println!(
        "Generating {} universities for {} users...",
        num_universities, NUM_USERS
    );

    // Phase 0: Generate universities (shadow table)
    let universities = generate_universities(num_universities, &mut rng);
    let university_names: Vec<String> = universities.keys().cloned().collect();
    println!("Generated universities: {:?}", university_names);

    // Phase 1: Generate partial users (without student_id, verification_status, etc.)
    let mut partial_users: Vec<PartialUser> = (0..NUM_USERS)
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
    let db: DatabaseConnection = Database::connect(DATABASE_URL).await?;

    println!("Inserting {} users...", complete_users.len());

    for user in complete_users {
        match user.insert(&db).await {
            Ok(inserted) => {
                println!(
                    "  {} | {} | {} | {}",
                    inserted.student_id, inserted.full_name, inserted.school_id, inserted.email
                );
            }
            Err(e) => {
                eprintln!("Failed to insert user: {}", e);
            }
        }
    }

    let count = user::Entity::find().all(&db).await?.len();

    // Pretty-print university registry
    println!("\n{}", "=".repeat(50));
    println!("University Registry:");
    println!("{}", "-".repeat(50));
    let mut sorted_registry: Vec<_> = university_registry.iter().collect();
    sorted_registry.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    for (name, count) in sorted_registry {
        println!("  {:<40} : {:>4} students", name, count);
    }
    println!("{}", "=".repeat(50));
    println!("Seeding complete. Total users in database: {}", count);

    Ok(())
}

fn generate_universities(num: usize, rng: &mut StdRng) -> UniversityRegistry {
    let suffixes = [
        "University",
        "Institute of Technology",
        "College",
        "Academy",
    ];
    let mut universities = HashMap::new();

    for _ in 0..num {
        // Use fake's internal rng wrapper for compatibility
        let company: String = CompanyName().fake();
        let suffix = suffixes.choose(rng).unwrap();
        let name = format!("{} {}", company, suffix);
        universities.insert(name, 0);
    }

    universities
}

fn generate_partial_user(
    index: usize,
    university_names: &[String],
    rng: &mut StdRng,
) -> PartialUser {
    // Use fake's default rng for name generation
    let full_name: String = Name().fake();

    // Generate first name and last name for email
    let name_parts: Vec<&str> = full_name.split_whitespace().collect();
    let first_name = name_parts.first().unwrap_or(&"Unknown");
    let last_name = name_parts.last().unwrap_or(&"User");

    // Create username from names
    let username = format!(
        "{}{}{}",
        first_name.to_lowercase(),
        last_name.to_lowercase(),
        index
    );

    // Create email
    let email = format!(
        "{}.{}@student.edu",
        first_name.to_lowercase(),
        last_name.to_lowercase()
    );

    // Generate phone number
    let phone = format!(
        "+1-{:03}-{:03}-{:04}",
        rng.random_range(200..999),
        rng.random_range(100..999),
        rng.random_range(1000..9999)
    );

    // Generate date of birth (age range 18-30, so birth years 1995-2007)
    let date_of_birth = NaiveDate::from_ymd_opt(
        rng.random_range(1995..2007),
        rng.random_range(1..12),
        rng.random_range(1..28),
    )
    .unwrap();

    // Pick a university
    let school_name = university_names.choose(rng).unwrap().clone();

    PartialUser {
        id: Uuid::new_v4(),
        username,
        email,
        phone,
        full_name,
        bio: Some(Sentence(3..10).fake()),
        date_of_birth,
        school_name,
        reputation_score: rng.random_range(0..100),
    }
}

fn finalize_user(
    partial: PartialUser,
    registry: &mut UniversityRegistry,
    rng: &mut StdRng,
) -> user::ActiveModel {
    let now = Utc::now();

    // Calculate admission year (birth year + 18)
    let admission_year = partial.date_of_birth.year() + 18;

    // Get next student index for this university and increment
    let student_index = registry.entry(partial.school_name.clone()).or_insert(0);
    *student_index += 1;
    let index = *student_index;

    // Format student_id: AAAAIIII (admission year 4 digits + index 4 digits)
    let student_id = format!("{:04}{:04}", admission_year, index);

    // Randomize verification status
    let is_verified: bool = rng.random_range(0..2) == 1;
    let verification_status = if is_verified { "verified" } else { "pending" };

    // Set verified_at for verified students (random month/day in admission year)
    let verified_at = if is_verified {
        let month = rng.random_range(1..13);
        let day = rng.random_range(1..29);
        Utc.with_ymd_and_hms(admission_year, month, day, 0, 0, 0)
            .single()
    } else {
        None
    };

    // Student status expires: admission year + random(4, 8) years
    let expires_year = admission_year + rng.random_range(4..9);
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
