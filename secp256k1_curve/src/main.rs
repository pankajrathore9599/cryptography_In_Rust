use k256::{ProjectivePoint, PublicKey, SecretKey, Scalar};
use rand_core::OsRng;

fn main() {
    // Generate a random secret key and its corresponding public key
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from(&sk);

    // Message to encrypt
    let message = b"Hello, world!";

    // Encrypt the message
    let encrypted_data = encrypt_data(&pk, message);
    println!("Encrypted data: {:?}", encrypted_data);

    // Decrypt the message
    let decrypted_data = decrypt_data(&sk, &encrypted_data);
    println!("Decrypted data: {:?}", decrypted_data);
}

fn encrypt_data(pk: &PublicKey, data: &[u8]) -> (ProjectivePoint, Vec<u8>) {
    let ephemeral_sk = SecretKey::random(&mut OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);
    let shared_secret = pk.as_projective() * ephemeral_sk.to_secret_scalar();

    let mut xor_key = shared_secret.to_bytes().to_vec();
    xor_key.truncate(data.len());
    let encrypted_data: Vec<u8> = data.iter().zip(xor_key.iter()).map(|(a, b)| a ^ b).collect();
    (ephemeral_pk.to_projective(), encrypted_data)
}

fn decrypt_data(sk: &SecretKey, encrypted_data: &(ProjectivePoint, Vec<u8>)) -> Vec<u8> {
    let (ephemeral_pk, ciphertext) = encrypted_data;
    let shared_secret = ephemeral_pk * sk.to_secret_scalar();

    let mut xor_key = shared_secret.to_bytes().to_vec();
    xor_key.truncate(ciphertext.len());
    let decrypted_data: Vec<u8> = ciphertext.iter().zip(xor_key.iter()).map(|(a, b)| a ^ b).collect();
    decrypted_data
}
