use std::{
    fs::File,
    io::{self, BufReader},
    path::Path,
};

use chrono::Utc;
use clap::{Parser, Subcommand};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_derive::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("error reading the DB file: {0}")]
    ReadDBError(#[from] io::Error),
    #[error("error parsing the DB file: {0}")]
    ParseDBError(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize, Debug)]
struct User {
    username: String,
    password: String,
}

// clap cli arguments parser
#[derive(Parser)]
struct Cli {
    /// Commands
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Login to get jwt token
    Login {
        #[clap(short, long, value_parser)]
        name: String,
        #[clap(short, long, value_parser)]
        password: String,
    },
    /// Access restricted data
    Access {
        /// Your jwt token
        #[clap(short, long, value_parser)]
        token: String,
    },
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

// jwt claims struct where we "register claims"
// sub(subject), iat(issued at) & exp(expiration time)
// role is bs
#[derive(Deserialize, Serialize, Debug)]
struct Claims {
    sub: String,
    iat: usize,
    exp: usize,
    role: String,
}

fn read_user_from_file<P: AsRef<Path>>(path: P) -> Result<User, Error> {
    // Open json file read-only mode
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let user = serde_json::from_reader(reader)?;
    Ok(user)
}

fn check_user_exisis(username: &String, password: &String) -> Result<bool, Error> {
    let stored_user = read_user_from_file("db/db.json").unwrap();

    if stored_user.username == username.to_owned() && stored_user.password == password.to_owned() {
        return Ok(true);
    }

    Ok(false)
}

fn gen_jwt(subject: &String) -> Result<String, ()> {
    let secret_key = b"secret-key";

    let current_iat = Utc::now().timestamp();
    // let new_exp = Utc::now()
    //     .checked_add_signed(Duration::seconds(1))
    //     .expect("invalid timestamp")
    //     .timestamp();
    let new_exp = current_iat + 2;

    let new_claim = Claims {
        sub: subject.to_string(),
        iat: current_iat as usize,
        exp: new_exp as usize,
        role: "User".to_owned(),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &new_claim,
        &EncodingKey::from_secret(secret_key),
    )
    .unwrap();

    Ok(token)
}

fn validate_jwt(token: &String) -> Result<bool, ()> {
    let secret_key = b"secret-key";

    match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret_key),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(data) => {
            println!("{:#?} {:#?}", data.claims.role, data.claims.exp);
            return Ok(true);
        }
        Err(err) => {
            println!("err: {:?}", err.kind());
            return Ok(false);
        }
    };
}

fn main() {
    let args = Cli::parse();

    match &args.command {
        Commands::Login { name, password } => {
            let is_user = check_user_exisis(name, password).unwrap();

            if is_user {
                let token = gen_jwt(name).unwrap();
                println!("Token : {:?}", token)
            } else {
                println!("User not found")
            }
        }

        Commands::Access { token } => {
            if validate_jwt(token).unwrap() {
                println!("your mom gay lmao")
            }
        }
    }
}
