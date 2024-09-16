use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use core::str;
use pgp::cleartext::CleartextSignedMessage;
use pgp::crypto::hash::HashAlgorithm;
use pgp::{
    crypto::sym::SymmetricKeyAlgorithm,
    types::{KeyTrait, SecretKeyTrait},
    ArmorOptions, Deserializable, Message, SignedPublicKey, SignedSecretKey,
};
use rand::prelude::ThreadRng;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::{Duration, SystemTime};
use std::{env, fs};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct AccountKit {
    domain: String,
    user_id: String,
    username: String,
    first_name: String,
    last_name: String,
    user_private_armored_key: String,
    user_public_armored_key: String,
    server_public_armored_key: String,
    security_token: SecurityToken,
}

#[derive(Debug, Deserialize)]
struct SecurityToken {
    code: String,
    color: String,
    textcolor: String,
}

#[derive(Debug, Deserialize)]
struct KeyBody {
    body: Key,
}

#[derive(Debug, Deserialize)]
struct ChallengeBody {
    body: Challenge,
}

#[derive(Debug, Deserialize)]
struct Key {
    keydata: String,
}

#[derive(Debug, Deserialize)]
struct Challenge {
    challenge: String,
}

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    version: String,
    domain: String,
    verify_token: String,
    access_token: String,
    refresh_token: String,
}

fn read_account_kit(path: &str) -> CleartextSignedMessage {
    let account_kit_bytes = fs::read(path).expect("Could not read account kit file");
    let account_kit_content = BASE64_STANDARD
        .decode(account_kit_bytes)
        .expect("Could not base64 decode account kit file");
    let (msg, _headers_msg) = CleartextSignedMessage::from_string(
        &String::from_utf8(account_kit_content).expect("Account kit is not UTF8 decodable."),
    )
    .expect("Could not parse account kit file as signed PGP message");
    msg
}

fn panic_on_keypair_issue(private_key: &SignedSecretKey, public_key: &SignedPublicKey) {
    if private_key.verify().is_err() {
        panic!("Could not verify user's private key.");
    }
    if !private_key.is_signing_key() {
        panic!("User's private key is not a signing key.");
    }
    if !public_key.is_encryption_key() {
        panic!("User's public key is not encryption key.");
    }
    if private_key.public_key().fingerprint() != public_key.fingerprint() {
        panic!("Generated public key and given public keys don't have matching fingerprint.");
    }
}

fn login(
    mut rng: &mut ThreadRng,
    account_kit: &AccountKit,
    client: &Client,
    user_private_key: &SignedSecretKey,
    user_key_passphrase: &String,
    server_public_key: &SignedPublicKey,
) -> ChallengeResponse {
    let challenge_token = Uuid::new_v4().to_string();
    let challenge_expiration_date = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Couldn't get time since epoch.")
        + Duration::from_secs(120);
    let challenge = json!({
        "version": "1.0.0",
        "domain": account_kit.domain,
        "verify_token": challenge_token,
        "verify_token_expiry": challenge_expiration_date.as_secs(),
    })
    .to_string();
    let challenge_message = Message::new_literal("", &challenge)
        .sign(
            &user_private_key,
            || user_key_passphrase.clone(),
            HashAlgorithm::SHA3_512,
        )
        .expect("Could not sign challenge message.")
        .encrypt_to_keys(
            &mut rng,
            SymmetricKeyAlgorithm::AES128,
            &[&server_public_key],
        )
        .expect("Could not encrypt challenge message.");
    let armored_challenge = challenge_message
        .to_armored_string(ArmorOptions::default())
        .expect("Could not armor encrypted challenge message.");
    let login_req = client
        .post(format!("{}/auth/jwt/login.json", account_kit.domain))
        .json(&json!({
            "user_id": account_kit.user_id,
            "challenge": armored_challenge,
        }));
    let login_res = login_req.send().expect("Could not send login request.");
    let challenge_response: ChallengeBody = login_res
        .json()
        .expect("Could not de-serialize server response.");

    let (armored_challenge_response, _headers) =
        Message::from_string(&challenge_response.body.challenge)
            .expect("Couldn't load armored challenge response.");
    let (decrypted_challenge_response, _key_ids) = armored_challenge_response
        .decrypt(|| user_key_passphrase.clone(), &[&user_private_key])
        .expect("Could not decrypt challenge response.");
    let literal_data_bytes = decrypted_challenge_response
        .get_literal()
        .expect("Could not get literal data from decrypted challenge.")
        .data();
    let literal_data = str::from_utf8(literal_data_bytes)
        .expect("Could not turn challenge response bytes to str.");
    let challenge_response: ChallengeResponse = serde_json::from_str(literal_data)
        .expect("Could not de-serialize challenge response to struct.");
    if challenge_response.version != "1.0.0" {
        panic!("Challenge version mismatch.");
    }
    if challenge_response.domain != format!("{}/", account_kit.domain) {
        panic!("Challenge response domain doesn't match the hostname we have.");
    }
    if challenge_response.verify_token != challenge_token {
        panic!("Challenge response token doesn't match the one we sent.");
    }
    challenge_response
}

fn refresh_access_token(
    account_kit: &AccountKit,
    client: &Client,
    mut challenge_response: ChallengeResponse,
) -> ChallengeResponse {
    let refresh_req = client
        .post(format!("{}/auth/jwt/refresh.json", account_kit.domain))
        .json(&json!({
            "user_id": account_kit.user_id,
            "refresh_token": challenge_response.refresh_token,
        }));
    let refresh_res = refresh_req.send().expect("Could not send refresh request.");
    {
        let refresh_cookie = refresh_res
            .cookies()
            .find(|cookie| cookie.name() == "refresh_token")
            .expect("Couldn't find new refresh token in cookies.");
        challenge_response.refresh_token = refresh_cookie.value().to_string();
    }
    let refresh_body = refresh_res
        .json::<Value>()
        .expect("Couldn't de-serialize refresh response.");
    let refresh_body_value = refresh_body
        .get("body")
        .expect("Couldn't get body for response.");
    let new_access_token = refresh_body_value
        .get("access_token")
        .expect("Couldn't get access_token from refresh response body.")
        .as_str()
        .expect("Could not convert access_token to str.");
    if new_access_token == challenge_response.access_token {
        println!("Access token didn't change during refresh.");
    } else {
        challenge_response.access_token = new_access_token.to_string();
    }
    challenge_response
}

fn main() {
    // Init
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Please provide private key passphrase as argument.")
    }
    let key_passphrase = &args[1];
    let mut rng = rand::thread_rng();
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Could not build HTTP client.");

    // Read account kit
    let account_kit_message = read_account_kit("./account-kit.passbolt");
    let account_kit: AccountKit = serde_json::from_str(account_kit_message.text())
        .expect("Could not deserialize account kit file.");
    println!(
        "Found account kit for {} {} <{}>.",
        account_kit.first_name, account_kit.last_name, account_kit.username
    );
    println!(
        "Security token for said account is {} with font color {} and background color {}.",
        account_kit.security_token.code,
        account_kit.security_token.textcolor,
        account_kit.security_token.color
    );
    let (account_kit_server_public_key, _headers) =
        SignedPublicKey::from_string(&account_kit.server_public_armored_key)
            .expect("Could not parse account kit server public key.");
    let (user_public_key, _headers) =
        SignedPublicKey::from_string(&account_kit.user_public_armored_key)
            .expect("Could not parse account kit server public key.");
    let (user_private_key, _headers) =
        SignedSecretKey::from_string(&account_kit.user_private_armored_key)
            .expect("Could not get user's signed key from account kit.");
    if account_kit_message.verify(&user_public_key).is_err() {
        panic!("Could not verify account kit message against public key in said kit.");
    }
    panic_on_keypair_issue(&user_private_key, &user_public_key);
    println!();

    // Get server's public key
    let verify_res = client
        .get(format!("{}/auth/verify.json", account_kit.domain))
        .send()
        .expect("Could not send verify request.");
    let body: KeyBody = verify_res
        .json()
        .expect("Could not de-serialize verify request body.");
    let (server_public_key, _headers) =
        SignedPublicKey::from_string(&body.body.keydata).expect("Couldn't parse public key.");
    if server_public_key.fingerprint() != account_kit_server_public_key.fingerprint() {
        panic!("Server public key fingerprint doesn't match its fingerprint in account kit.");
    }
    if !server_public_key.is_encryption_key() {
        panic!("Server public key is not encryption key.");
    }

    // Log in
    let challenge_response = login(
        &mut rng,
        &account_kit,
        &client,
        &user_private_key,
        key_passphrase,
        &server_public_key,
    );
    println!("Access token: {:?}", challenge_response.access_token);
    println!();

    // Refresh access tokens
    let challenge_response = refresh_access_token(&account_kit, &client, challenge_response);
    println!(
        "Refreshed access token: {:?}",
        challenge_response.access_token
    );
    println!();

    // Get information about us
    let me_res = client
        .get(format!("{}/users/me.json", account_kit.domain))
        .bearer_auth(&challenge_response.access_token)
        .send()
        .expect("Could not send users request.");
    println!(
        "Me: {:#?}",
        me_res
            .json::<Value>()
            .expect("Could not de-serialize user data.")
    );
    println!();

    // Log out
    let logout_req = client
        .post(format!("{}/auth/jwt/logout.json", account_kit.domain))
        .bearer_auth(&challenge_response.access_token)
        .json(&json!({
           "refresh_token": challenge_response.refresh_token,
        }));
    let logout_res = logout_req.send().expect("Could not send logout request.");
    if logout_res.status() != StatusCode::OK {
        panic!("Could not log out.")
    }
}
