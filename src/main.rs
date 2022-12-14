use anyhow::anyhow;
use chacha20poly1305::{
    aead::{stream, Aead},
    KeyInit, XChaCha20Poly1305,
};
use rand::{rngs::OsRng, RngCore};
use std::{
    fs::{self, File},
    io::{Read, Write},
};

fn main() -> Result<(), anyhow::Error> {
    let mut small_file_key = [0u8; 32];
    let mut small_file_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut small_file_key);
    OsRng.fill_bytes(&mut small_file_nonce);

    encrypt_small_file("100.bin", "100.enc", &small_file_key, &small_file_nonce)?;
    decrypt_small_file("100.enc", "100.dec.bin", &small_file_key, &small_file_nonce)?;

    encrypt_small_file(
        "sample.txt",
        "sample.enc",
        &small_file_key,
        &small_file_nonce,
    )?;
    decrypt_small_file(
        "sample.enc",
        "sample.dec.txt",
        &small_file_key,
        &small_file_nonce,
    )?;

    let mut large_file_key = [0u8; 32];
    let mut large_file_nonce = [0u8; 19];
    OsRng.fill_bytes(&mut large_file_key);
    OsRng.fill_bytes(&mut large_file_nonce);

    encrypt_large_file("2048.bin", "2048.enc", &large_file_key, &large_file_nonce)?;
    decrypt_large_file(
        "2048.enc",
        "2048.dec.bin",
        &large_file_key,
        &large_file_nonce,
    )?;

    // encrypt_large_file("AKAI.vrm", "AKAI.enc", &large_file_key, &large_file_nonce)?;
    // decrypt_large_file(
    //     "AKAI.enc",
    //     "AKAI.dec.vrm",
    //     &large_file_key,
    //     &large_file_nonce,
    // )?;

    Ok(())
}

fn encrypt_small_file(
    src_filepath: &str,
    dist_filepath: &str,
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<(), anyhow::Error> {
    println!("Encrypting {} to {}", src_filepath, dist_filepath);
    let cipher = XChaCha20Poly1305::new(key.into());

    let file_data = fs::read(src_filepath)?;

    let encrypted_file = cipher
        .encrypt(nonce.into(), file_data.as_ref())
        .map_err(|err| anyhow!("Encrypting small file: {}", err))?;

    fs::write(&dist_filepath, encrypted_file)?;

    Ok(())
}

fn decrypt_small_file(
    src_filepath: &str,
    dist_filepath: &str,
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<(), anyhow::Error> {
    println!("Decrypting {} to {}", src_filepath, dist_filepath);
    let cipher = XChaCha20Poly1305::new(key.into());

    let file_data = fs::read(src_filepath)?;

    let decrypted_file = cipher
        .decrypt(nonce.into(), file_data.as_ref())
        .map_err(|err| anyhow!("Decrypting small file: {}", err))?;

    fs::write(&dist_filepath, decrypted_file)?;

    Ok(())
}

fn encrypt_large_file(
    src_filepath: &str,
    dist_filepath: &str,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    println!("Encrypting {} to {}", src_filepath, dist_filepath);
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut source_file = File::open(src_filepath)?;
    let mut dist_file = File::create(dist_filepath)?;

    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write_all(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write_all(&ciphertext)?;
            break;
        }
    }

    Ok(())
}

fn decrypt_large_file(
    src_filepath: &str,
    dist_filepath: &str,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    println!("Decrypting {} to {}", src_filepath, dist_filepath);
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut encrypted_file = File::open(src_filepath)?;
    let mut dist_file = File::create(dist_filepath)?;

    loop {
        let read_count = encrypted_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write_all(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write_all(&plaintext)?;
            break;
        }
    }

    Ok(())
}
