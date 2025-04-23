package com.tfg.infractory.common.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.AEADBadTagException; // Import specific exception
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class EncryptionService { // Renamed for clarity

    private static final Logger logger = LoggerFactory.getLogger(EncryptionService.class);
    private static final String ALGORITHM = "AES";
    // Use AES/GCM/NoPadding for Authenticated Encryption (Confidentiality +
    // Integrity)
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    // AES-256 requires a 32-byte key
    private static final int KEY_LENGTH_BYTES = 32;
    // Recommended nonce length for GCM is 12 bytes (96 bits)
    private static final int GCM_NONCE_LENGTH_BYTES = 12;
    // Recommended authentication tag length for GCM is 16 bytes (128 bits)
    private static final int GCM_TAG_LENGTH_BITS = 128;

    @Value("${infractory.encryption.key}")
    private String encryptionKeyString; // Raw key string from config

    private SecretKey secretKey;
    private SecureRandom secureRandom;

    // IMPORTANT: The encryption key stored in "${infractory.encryption.key}"
    // MUST be a Base64 encoded representation of EXACTLY 32 cryptographically
    // random bytes.
    // Generating and storing this key securely is CRITICAL and outside the scope of
    // this code.
    // DO NOT store plaintext keys directly in configuration files in production.
    // Use a secrets management system (Vault, AWS/GCP/Azure Secrets Manager, etc.).
    @jakarta.annotation.PostConstruct
    private void init() {
        try {
            // Assume the key in config is Base64 encoded for safe transport/storage
            byte[] keyBytes = Base64.getDecoder().decode(encryptionKeyString);

            if (keyBytes.length != KEY_LENGTH_BYTES) {
                String errorMsg = String.format(
                        "Fatal: Invalid encryption key length. Expected %d bytes, but got %d bytes. " +
                                "Ensure the configured key ('infractory.encryption.key') is a Base64 encoded string of exactly %d random bytes.",
                        KEY_LENGTH_BYTES, keyBytes.length, KEY_LENGTH_BYTES);
                logger.error(errorMsg);
                // Fail fast - do not proceed with an invalid key
                throw new IllegalArgumentException(errorMsg);
            }

            this.secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
            this.secureRandom = new SecureRandom(); // Use a cryptographically strong random number generator
            logger.info("SecureEncryptionService initialized successfully with AES-256 GCM.");

        } catch (IllegalArgumentException e) {
            // Catch Base64 decoding errors or our explicit length error
            logger.error(
                    "Fatal error decoding or validating encryption key. Is it valid Base64? Does it have the correct length ({} bytes)?",
                    KEY_LENGTH_BYTES, e);
            throw new RuntimeException("Fatal error initializing encryption key: " + e.getMessage(), e);
        } catch (Exception e) {
            // Catch any other unexpected errors during init
            logger.error("Fatal unexpected error during encryption service initialization.", e);
            throw new RuntimeException("Fatal unexpected error initializing encryption service", e);
        }
    }

    /**
     * Encrypts data using AES-256 GCM. The nonce is prepended to the ciphertext.
     *
     * @param dataToEncrypt The plaintext string to encrypt.
     * @return A Base64 encoded string containing the nonce followed by the
     *         ciphertext, or null if input is null.
     * @throws RuntimeException if encryption fails.
     */
    public String encrypt(String dataToEncrypt) {
        if (dataToEncrypt == null) {
            return null;
        }
        if (secretKey == null) {
            throw new IllegalStateException("Encryption service not properly initialized. Secret key is missing.");
        }

        try {
            // 1. Generate a unique random nonce for each encryption
            byte[] nonce = new byte[GCM_NONCE_LENGTH_BYTES];
            secureRandom.nextBytes(nonce);

            // 2. Create GCMParameterSpec
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);

            // 3. Get Cipher instance and initialize
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

            // 4. Encrypt the data
            byte[] encryptedBytes = cipher.doFinal(dataToEncrypt.getBytes(StandardCharsets.UTF_8));

            // 5. Prepend the nonce to the ciphertext
            ByteBuffer byteBuffer = ByteBuffer.allocate(nonce.length + encryptedBytes.length);
            byteBuffer.put(nonce);
            byteBuffer.put(encryptedBytes);
            byte[] cipherMessage = byteBuffer.array();

            // 6. Base64 encode the combined nonce + ciphertext
            return Base64.getEncoder().encodeToString(cipherMessage);

        } catch (Exception e) {
            // Log exceptions appropriately without leaking sensitive info
            logger.error("Error encrypting data.", e);
            // Avoid throwing generic RuntimeException in production if specific handling is
            // needed downstream
            throw new RuntimeException("Error encrypting data", e);
        }
    }

    /**
     * Decrypts data encrypted with AES-256 GCM, expecting the nonce prepended to
     * the ciphertext.
     * Verifies the integrity using the GCM authentication tag.
     *
     * @param dataToDecrypt The Base64 encoded string (nonce + ciphertext).
     * @return The original plaintext string, or null if input is null.
     * @throws RuntimeException if decryption fails (e.g., bad format, integrity
     *                          check failure).
     */
    public String decrypt(String dataToDecrypt) {
        if (dataToDecrypt == null) {
            return null;
        }
        if (secretKey == null) {
            throw new IllegalStateException("Encryption service not properly initialized. Secret key is missing.");
        }

        try {
            // 1. Base64 decode the input
            byte[] cipherMessage = Base64.getDecoder().decode(dataToDecrypt);

            // Basic check: Must be at least nonce length + 1 byte ciphertext
            if (cipherMessage.length < GCM_NONCE_LENGTH_BYTES + 1) {
                throw new IllegalArgumentException("Invalid encrypted data format: too short.");
            }

            // 2. Extract the nonce and the ciphertext
            ByteBuffer byteBuffer = ByteBuffer.wrap(cipherMessage);
            byte[] nonce = new byte[GCM_NONCE_LENGTH_BYTES];
            byteBuffer.get(nonce);
            byte[] encryptedBytes = new byte[byteBuffer.remaining()];
            byteBuffer.get(encryptedBytes);

            // 3. Create GCMParameterSpec with extracted nonce
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);

            // 4. Get Cipher instance and initialize for decryption
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

            // 5. Decrypt the data (GCM automatically verifies the auth tag here)
            byte[] originalBytes = cipher.doFinal(encryptedBytes);

            // 6. Convert back to String
            return new String(originalBytes, StandardCharsets.UTF_8);

        } catch (IllegalArgumentException e) {
            // Handles Base64 decoding errors or our length check
            logger.error("Error decrypting data: Invalid format or Base64 encoding.", e);
            throw new RuntimeException("Decryption failed due to invalid input format", e);
        } catch (AEADBadTagException e) {
            // IMPORTANT: This indicates integrity failure (tampering) or wrong key/nonce!
            logger.error(
                    "Error decrypting data: Integrity check failed (AEADBadTagException). Possible data tampering or incorrect key/nonce.",
                    e);
            throw new RuntimeException("Decryption failed: Integrity check failed", e);
        } catch (Exception e) {
            // Catch other potential crypto exceptions
            logger.error("Error decrypting data.", e);
            throw new RuntimeException("Error decrypting data", e);
        }
    }
}