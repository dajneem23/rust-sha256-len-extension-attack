pub mod utils;

use hex;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Clone)]
pub struct ForgedResult {
    message: Vec<u8>,
    digest: Vec<u8>,
}

#[wasm_bindgen]
impl ForgedResult {
    #[wasm_bindgen(constructor)]
    pub fn new(message: Vec<u8>, digest: Vec<u8>) -> ForgedResult {
        ForgedResult { message, digest }
    }

    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn digest(&self) -> Vec<u8> {
        self.digest.clone()
    }
}

/// Simulates a secret known only to the server
const SECRET: &[u8] = b"supersecretkey!!"; // Using a 16-byte key for clarity

/// Naive MAC vulnerable to length extension attacks.
/// H(secret || message)
fn sha256_mac(msg: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(SECRET);
    hasher.update(msg);
    hasher.finalize().to_vec()
}

/// Correctly calculates the SHA-2 padding for a message of a given length.
fn sha256_padding(message_len: usize) -> Vec<u8> {
    let mut padding = Vec::new();

    // Append a single 1 bit (the byte 0x80)
    padding.push(0x80);

    // The total length in bytes processed so far is message_len + 1 (for the 0x80).
    // We need to pad until the length is 56 mod 64.
    // The final 8 bytes are for the length encoding.
    let mod_len = (message_len + 1) % 64;
    let mut pad_len = if mod_len > 56 {
        (64 - mod_len) + 56
    } else {
        56 - mod_len
    };
    padding.extend(vec![0; pad_len]);

    // Append the original message length in bits as a 64-bit big-endian integer.
    let bit_len = (message_len as u64) * 8;
    padding.extend_from_slice(&bit_len.to_be_bytes());

    padding
}

/// Secure MAC implementation using HMAC-SHA256.
fn hmac_sha256(msg: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// Performs the length extension attack.
#[wasm_bindgen]
pub fn length_extension_attack(
    original_message: &[u8],
    original_mac: &[u8],
    data_to_append: &[u8],
    guessed_secret_len: usize,
) -> ForgedResult {
    // Step 1: Initialize SHA-256 internal state from the original MAC.
    // The output of SHA-256 is the final internal state (h0, h1, ..., h7).
    let mut forged_state = [0u32; 8];
    for (chunk, val) in original_mac.chunks(4).zip(forged_state.iter_mut()) {
        *val = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    // Step 2: Calculate the padding for the original message (secret || original_message).
    // This is what the server would have added internally. We need to append this
    // to our known message part to create the full message for the attack.
    let original_total_len = guessed_secret_len + original_message.len();
    let padding = sha256_padding(original_total_len);

    // Step 3: Create the forged message.
    // forged_message = original_message || padding || data_to_append
    let mut forged_message = original_message.to_vec();
    forged_message.extend_from_slice(&padding);
    forged_message.extend_from_slice(data_to_append);

    // Step 4: Continue the hash computation from the captured state.
    // We need to tell the new hash computation how long the *original* data was,
    // so it pads correctly at the end. The length passed to the compression
    // function is the length of the data it is currently processing, starting
    // from a state that has already processed `original_total_len + padding.len()` bytes.
    let mut hasher = Sha256::new();

    // The data to be processed now is just the appended part.
    // The final padding will be calculated based on the *new total length*.
    // The total length for the new hash is:
    // (length of original secret + message + padding) + (length of appended data)
    let new_hash_len_offset = (original_total_len + padding.len()) as u64;

    // We can't directly set the state and length of a `sha2::Sha256` hasher.
    // Instead, we manually run the compression function on our appended data.
    // This is the core of the attack.

    // We create a new block of data containing our appended message, plus new padding.
    // The new padding must be calculated based on the total forged message length.
    let mut new_data_with_padding = data_to_append.to_vec();
    // The length for this new padding is `new_hash_len_offset + data_to_append.len()`
    new_data_with_padding.extend_from_slice(&sha256_padding(
        new_hash_len_offset as usize + data_to_append.len(),
    ));

    // Process the new data in 64-byte blocks, updating the state we recovered from the MAC.
    for chunk in new_data_with_padding.chunks(64) {
        let mut block = [0u8; 64];
        block[..chunk.len()].copy_from_slice(chunk);
        sha2::compress256(&mut forged_state, &[block.into()]);
    }

    // The final state is our new, forged MAC.
    let forged_mac: Vec<u8> = forged_state.iter().flat_map(|h| h.to_be_bytes()).collect();

    println!("🚨 Length Extension Attack Details:");
    println!("  - Guessed Secret Length: {}", guessed_secret_len);
    println!(
        "  - Original Message (hex): {}",
        hex::encode(original_message)
    );
    println!("  - Glue Padding (hex):     {}", hex::encode(&padding));
    println!(
        "  - Appended Data (hex):    {}",
        hex::encode(data_to_append)
    );
    println!("\n✅ Attack Successful!");
    println!("Forged Message (hex):   {}", hex::encode(&forged_message));
    println!("Forged MAC (hex):       {}", hex::encode(&forged_mac));

    ForgedResult::new(forged_message, forged_mac)
}

mod tests {
    use super::*;

    #[test]
    fn test_sha256_mac() {
        let msg = b"test message";
        let mac = sha256_mac(msg);
        assert_eq!(
            hex::encode(mac),
            "c1b2f8d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0"
        );
    }

    #[test]
    fn test_hmac_sha256() {
        let msg = b"test message";
        let mac = hmac_sha256(msg);
        assert_eq!(
            hex::encode(mac),
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
        );
    }

    #[test]
    fn test_overall(){
    let message = b"user=alice&amount=1000";
    let extra = b"&admin=true";

    println!(
        "🔐 Original message: {:?}",
        String::from_utf8_lossy(message)
    );
    let original_mac = sha256_mac(message);
    println!(
        "Naive MAC [SHA256(secret || msg)]: {}",
        hex::encode(&original_mac)
    );

    println!("\n🔓 Attempting Length Extension Attack...");
    // The attacker needs to guess the length of the secret. Here, we "guess" correctly.
    let res = length_extension_attack(message, &original_mac, extra, SECRET.len());

    let forged_message = res.message();
    let forged_mac = res.digest();
    // Verification step: Let's see if the forged MAC matches what the server would compute
    // for the forged message. Note that the server receives the message with the padding inside it.
    let server_side_verification_mac = sha256_mac(&forged_message);
    println!(
        "Server-side Check MAC:  {}",
        hex::encode(&server_side_verification_mac)
    );
    assert_eq!(
        forged_mac, server_side_verification_mac,
        "Attack failed: MACs do not match!"
    );
    println!("✅ Verification successful: Forged MAC is correct!");
    println!("\n🛡️ HMAC-SHA256 (Secure against this attack):");
    let secure_mac = hmac_sha256(message);
    println!("HMAC(secret, msg): {}", hex::encode(secure_mac));
    println!(
        "HMAC is not vulnerable because the secret is used both at the beginning and end of the hash computation."
    );
}
}