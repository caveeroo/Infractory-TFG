package com.tfg.infractory.infrastructure.ssh.service;

import com.tfg.infractory.infrastructure.ssh.model.SSHKey;
import com.tfg.infractory.infrastructure.ssh.repository.SSHKeyRepository;
import com.tfg.infractory.infrastructure.cloud.service.DigitalOceanCloudProviderService;
import com.tfg.infractory.infrastructure.secrets.service.SecretsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.regex.Pattern;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.UUID;

import java.io.StringWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Service
public class SSHKeyService {

    private static final Logger logger = LoggerFactory.getLogger(SSHKeyService.class);
    private static final String SSH_SECRET_TYPE = "SSH_PRIVATE_KEY";

    @Autowired
    private SSHKeyRepository sshKeyRepository;

    @Autowired
    private SecretsService secretsService;

    private final DigitalOceanCloudProviderService digitalOceanService;

    @Autowired
    public SSHKeyService(SSHKeyRepository sshKeyRepository,
            SecretsService secretsService,
            @Lazy DigitalOceanCloudProviderService digitalOceanService) {
        this.sshKeyRepository = sshKeyRepository;
        this.secretsService = secretsService;
        this.digitalOceanService = digitalOceanService;
    }

    @Transactional
    public SSHKey addSSHKey(String name, String publicKey, String privateKey) throws IllegalArgumentException {
        // Trim inputs
        name = name.trim();
        publicKey = publicKey.trim();
        privateKey = privateKey.trim();

        if (!isValidPublicKey(publicKey)) {
            throw new IllegalArgumentException("Invalid SSH public key format");
        }
        if (!isValidPrivateKey(privateKey)) {
            throw new IllegalArgumentException("Invalid SSH private key format");
        }

        // Generate a unique secret name
        String secretName = "ssh_pk_" + name.replaceAll("\\s+", "_") + "_"
                + UUID.randomUUID().toString().substring(0, 8);
        logger.info("Generated secret name for SSH key '{}': {}", name, secretName);

        // Store the encrypted private key as a secret
        try {
            // Use the raw private key string directly here
            secretsService.addSecret(secretName, SSH_SECRET_TYPE, privateKey);
            logger.info("Encrypted private key stored as secret: {}", secretName);
        } catch (Exception e) {
            logger.error("Failed to save encrypted private key secret '{}': {}", secretName, e.getMessage(), e);
            // If saving the secret fails, we shouldn't save the SSHKey object pointing to
            // it
            throw new RuntimeException("Failed to save SSH private key secret", e);
        }

        // Create SSHKey entity, setting the secret name, not the raw key
        SSHKey sshKey = new SSHKey();
        sshKey.setName(name);
        sshKey.setPublicKey(publicKey);
        // Store the reference to the secret
        sshKey.setPrivateKeySecretName(secretName);

        // The fingerprint will be automatically generated
        SSHKey savedKey = sshKeyRepository.save(sshKey);
        logger.info("SSH key entity added/updated: {}", savedKey.getName());

        return savedKey;
    }

    public List<SSHKey> getAllSSHKeys() {
        return sshKeyRepository.findAll();
    }

    public SSHKey getSSHKeyById(Long id) {
        return sshKeyRepository.findById(id).orElse(null);
    }

    @Transactional
    public void deleteSSHKey(Long id) {
        SSHKey sshKey = sshKeyRepository.findById(id).orElse(null);
        if (sshKey != null) {
            String secretName = sshKey.getPrivateKeySecretName();

            // Delete the corresponding secret if it exists
            if (secretName != null && !secretName.isEmpty()) {
                try {
                    secretsService.deleteSecretByName(secretName);
                    logger.info("Deleted SSH private key secret: {}", secretName);
                } catch (Exception e) {
                    // Log the error but potentially continue deletion of the SSHKey entity
                    logger.error("Failed to delete SSH private key secret '{}' during SSHKey deletion: {}", secretName,
                            e.getMessage(), e);
                }
            } else {
                logger.warn("No associated secret name found for SSH key ID {}, skipping secret deletion.", id);
            }

            // Delete the SSHKey entity from the repository
            sshKeyRepository.deleteById(id);
            logger.info("Deleted SSH key entity with ID: {}", id);

            // Delete from cloud provider (consider if this should happen only if DB
            // deletion is successful)
            try {
                // Check if digitalOceanService is initialized (due to @Lazy)
                if (digitalOceanService != null) {
                    digitalOceanService.deleteSshKeyFromProvider(sshKey);
                } else {
                    logger.warn(
                            "DigitalOceanService is null (possibly due to lazy loading issue or configuration), skipping deletion from provider for key ID: {}",
                            id);
                }
            } catch (Exception e) {
                logger.error("Failed to delete SSH key from DigitalOcean for key ID {}: {}", id, e.getMessage(), e);
                // Decide if this should cause the transaction to roll back
            }
        } else {
            logger.warn("Attempted to delete non-existent SSH key with ID: {}", id);
        }
    }

    private boolean isValidPublicKey(String publicKey) {
        // Regex pattern for SSH public key
        String sshPattern = "^(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-ed25519)\\s+([A-Za-z0-9+/]+[=]{0,3})\\s*(.*?)$";
        // Check if the key matches the pattern
        return Pattern.matches(sshPattern, publicKey.trim());
    }

    private boolean isValidPrivateKey(String privateKey) {
        // Trim the key and replace any Windows line endings with Unix line endings
        String trimmedKey = privateKey.trim().replace("\r\n", "\n");
        // Basic check for standard formats (OpenSSH or PKCS#1/PKCS#8 RSA)
        return (trimmedKey.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----")
                && trimmedKey.endsWith("-----END OPENSSH PRIVATE KEY-----")) ||
                (trimmedKey.startsWith("-----BEGIN RSA PRIVATE KEY-----")
                        && trimmedKey.endsWith("-----END RSA PRIVATE KEY-----"))
                ||
                (trimmedKey.startsWith("-----BEGIN PRIVATE KEY-----")
                        && trimmedKey.endsWith("-----END PRIVATE KEY-----"));
        // More robust validation could involve trying to parse the key
    }

    // This method likely doesn't need changes as it deals with the SSHKey object
    // after it's saved and potentially has the secret name
    public String uploadKeyToDigitalOcean(SSHKey sshKey) {
        // Check if digitalOceanService is initialized
        if (digitalOceanService == null) {
            logger.error("DigitalOceanService is null in uploadKeyToDigitalOcean. Cannot upload key: {}",
                    sshKey.getName());
            return null;
        }
        String doKeyId = digitalOceanService.uploadSshKeyIfNeeded(sshKey);
        if (doKeyId == null) {
            logger.warn("Failed to upload SSH key to DigitalOcean: {}", sshKey.getName());
        } else {
            logger.info("SSH key synced with DigitalOcean: {} (ID: {})", sshKey.getName(), doKeyId);
        }
        return doKeyId;
    }

    @Transactional
    public SSHKey generateAndAddSSHKey(String name) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // --- Generate Public Key in OpenSSH format ---
        // Reference: Based on JSch library logic and standard formats
        byte[] eBytes = ((java.security.interfaces.RSAPublicKey) keyPair.getPublic()).getPublicExponent().toByteArray();
        byte[] nBytes = ((java.security.interfaces.RSAPublicKey) keyPair.getPublic()).getModulus().toByteArray();

        String publicKeyContent;
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
                DataOutputStream dos = new DataOutputStream(bos)) {

            byte[] sshRsa = "ssh-rsa".getBytes(StandardCharsets.US_ASCII);
            dos.writeInt(sshRsa.length);
            dos.write(sshRsa);
            dos.writeInt(eBytes.length);
            dos.write(eBytes);
            // Handle potential leading zero byte for positive modulus in SSH format
            if ((nBytes[0] & 0x80) == 0x80) {
                byte[] tmp = new byte[nBytes.length + 1];
                tmp[0] = 0;
                System.arraycopy(nBytes, 0, tmp, 1, nBytes.length);
                nBytes = tmp;
            }
            dos.writeInt(nBytes.length);
            dos.write(nBytes);
            publicKeyContent = "ssh-rsa " + Base64.getEncoder().encodeToString(bos.toByteArray()) + " generated-key";
        } catch (IOException e) {
            logger.error("IOException generating public key bytes: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate public key content", e);
        }

        // --- Generate Private Key in PEM (PKCS#8) format ---
        // This is more standard and compatible than just base64 encoding DER
        String privateKeyContent;
        try (StringWriter stringWriter = new StringWriter();
                JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(keyPair.getPrivate());
            pemWriter.flush(); // Ensure content is written to the writer
            privateKeyContent = stringWriter.toString();
        } catch (IOException e) {
            logger.error("IOException generating PEM private key: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate private key content", e);
        } // requires BouncyCastle dependency: org.bouncycastle:bcpkix-jdk18on

        // Use the existing addSSHKey method which now handles secret creation
        return addSSHKey(name.trim(), publicKeyContent, privateKeyContent);
    }
}