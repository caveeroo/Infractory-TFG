package com.tfg.infractory.infrastructure.nebula.service;

import java.util.Set;
import java.util.List;
import org.slf4j.Logger;
import java.util.Arrays;
import java.nio.file.Path;
import java.util.Optional;
import java.nio.file.Files;
import java.util.ArrayList;
import java.io.IOException;
import java.io.BufferedReader;
import org.slf4j.LoggerFactory;
import java.io.InputStreamReader;
import java.nio.file.StandardCopyOption;
import jakarta.transaction.Transactional;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.core.io.ResourceLoader;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.concurrent.ConcurrentHashMap;

import com.tfg.infractory.infrastructure.secrets.model.Secret;
import com.tfg.infractory.infrastructure.secrets.service.SecretsService;

@Service
public class NebulaCertificateService {

    private static final Logger logger = LoggerFactory.getLogger(NebulaCertificateService.class);

    @Autowired
    private SecretsService secretsService;

    @Autowired
    private ResourceLoader resourceLoader;

    private static final String NEBULA_CERT_RESOURCE_PATH = "classpath:nebula/nebula-cert";

    // Add a map for client certificate locks
    private static final ConcurrentHashMap<String, Object> clientCertLocks = new ConcurrentHashMap<>();

    // Get or create a lock object for the given name
    private Object getClientCertLock(String name) {
        return clientCertLocks.computeIfAbsent(name, k -> new Object());
    }

    @Transactional
    public synchronized void generateAndSaveCA() {
        // Using synchronized method to ensure thread safety at the method level

        Optional<Secret> existingCaKey = secretsService.getSecretByName("nebula_ca_key");
        Optional<Secret> existingCaCert = secretsService.getSecretByName("nebula_ca_cert");

        if (existingCaKey.isPresent() && existingCaCert.isPresent()) {
            logger.info("CA already exists. Skipping CA generation (synchronized).");
            return;
        }

        try {
            Path tempDir = Files.createTempDirectory("nebula-ca");
            Path caKeyPath = tempDir.resolve("ca.key");
            Path caCertPath = tempDir.resolve("ca.crt");

            // Check again before proceeding in case another thread created the CA between
            // checks
            existingCaKey = secretsService.getSecretByName("nebula_ca_key");
            existingCaCert = secretsService.getSecretByName("nebula_ca_cert");

            if (existingCaKey.isPresent() && existingCaCert.isPresent()) {
                logger.info("CA was created by another thread while preparing. Skipping CA generation.");
                cleanupTempFiles(null, tempDir);
                return;
            }

            Path tempNebulaCert = extractNebulaCertBinary();
            ProcessBuilder pb = new ProcessBuilder(
                    tempNebulaCert.toString(),
                    "ca",
                    "-name", "Nebula CA",
                    "-out-key", caKeyPath.toString(),
                    "-out-crt", caCertPath.toString());
            Process process = pb.start();

            // Capture output to help with debugging
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                    logger.info("CA generation output: {}", line);
                }
            }

            StringBuilder errorOutput = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    errorOutput.append(line).append("\n");
                    logger.error("CA generation error: {}", line);
                }
            }

            int exitCode = process.waitFor();

            if (exitCode == 0) {
                String caKey = new String(Files.readAllBytes(caKeyPath));
                String caCert = new String(Files.readAllBytes(caCertPath));

                // Double check again before saving - in extreme cases another process could
                // have created the CA
                existingCaKey = secretsService.getSecretByName("nebula_ca_key");
                existingCaCert = secretsService.getSecretByName("nebula_ca_cert");

                if (existingCaKey.isPresent() && existingCaCert.isPresent()) {
                    logger.info("CA was created by another process while generating. Using the existing CA.");
                } else {
                    secretsService.addSecret("nebula_ca_key", "NEBULA_CA_KEY", caKey);
                    secretsService.addSecret("nebula_ca_cert", "NEBULA_CA_CERT", caCert);
                    logger.info("CA generated and saved successfully (synchronized).");
                }
            } else {
                logger.error("Failed to generate CA. Exit code: {}. Output: {}, Error: {}",
                        exitCode, output.toString(), errorOutput.toString());
                throw new RuntimeException("Failed to generate CA. Exit code: " + exitCode);
            }

            Files.deleteIfExists(tempNebulaCert);
            cleanupTempFiles(tempNebulaCert, tempDir);
        } catch (IOException | InterruptedException e) {
            logger.error("Error generating CA", e);
            throw new RuntimeException("Error generating CA", e);
        }
    }

    private Path extractNebulaCertBinary() throws IOException {
        Resource resource = resourceLoader.getResource(NEBULA_CERT_RESOURCE_PATH);
        if (!resource.exists()) {
            throw new RuntimeException("nebula-cert binary not found at " + NEBULA_CERT_RESOURCE_PATH);
        }

        Path tempNebulaCert = Files.createTempFile("nebula-cert", "");
        Files.copy(resource.getInputStream(), tempNebulaCert, StandardCopyOption.REPLACE_EXISTING);
        tempNebulaCert.toFile().setExecutable(true);
        return tempNebulaCert;
    }

    public void generateAndSaveClientCert(String name, String ipWithSubnet, Set<String> groups) {
        // Get a lock specific to this client name
        Object lock = getClientCertLock(name);
        synchronized (lock) {
            // Check if certificates already exist for this name
            Optional<Secret> existingCert = secretsService.getSecretByName("nebula_" + name + "_cert");
            Optional<Secret> existingKey = secretsService.getSecretByName("nebula_" + name + "_key");

            if (existingCert.isPresent() && existingKey.isPresent()) {
                logger.info("Client certificates already exist for: {}", name);
                return;
            }

            try {
                Path tempNebulaCert = extractNebulaCertBinary();
                Path tempDir = Files.createTempDirectory("nebula_certs_" + name + "_");

                // If client certs exist but one is missing, delete both to recreate
                if (existingCert.isPresent() || existingKey.isPresent()) {
                    logger.warn("Found incomplete client certificate set for: {}. Recreating both.", name);
                    existingCert = secretsService.getSecretByName("nebula_" + name + "_cert");
                    existingKey = secretsService.getSecretByName("nebula_" + name + "_key");

                    if (existingCert.isPresent()) {
                        secretsService.deleteSecret(existingCert.get().getId());
                    }
                    if (existingKey.isPresent()) {
                        secretsService.deleteSecret(existingKey.get().getId());
                    }
                }

                // Load CA key and cert (will generate if needed)
                Pair<Secret, Secret> caPair = loadCAKeyAndCert();

                // Write CA key and cert to temp files
                Path caCrtPath = tempDir.resolve("ca.crt");
                Path caKeyPath = tempDir.resolve("ca.key");
                Files.write(caCrtPath, caPair.getSecond().getContent().getBytes());
                Files.write(caKeyPath, caPair.getFirst().getContent().getBytes());

                // One last check before proceeding (in case another thread created certs
                // meanwhile)
                existingCert = secretsService.getSecretByName("nebula_" + name + "_cert");
                existingKey = secretsService.getSecretByName("nebula_" + name + "_key");
                if (existingCert.isPresent() && existingKey.isPresent()) {
                    logger.info("Client certificates created by another thread for: {}", name);
                    cleanupTempFiles(tempNebulaCert, tempDir);
                    return;
                }

                // Build and execute the nebula-cert command
                List<String> cmd = buildNebulaCertCommand(tempNebulaCert, name, ipWithSubnet, groups, tempDir);

                logger.info("Executing command to generate client cert for {}: {}", name, String.join(" ", cmd));

                ProcessBuilder pb = new ProcessBuilder(cmd);
                pb.redirectErrorStream(true);

                Process process = pb.start();

                StringBuilder output = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\n");
                        logger.info("nebula-cert output: {}", line);
                    }
                }

                int exitCode = process.waitFor();

                if (exitCode == 0) {
                    // Check one more time before saving
                    existingCert = secretsService.getSecretByName("nebula_" + name + "_cert");
                    existingKey = secretsService.getSecretByName("nebula_" + name + "_key");

                    if (existingCert.isPresent() && existingKey.isPresent()) {
                        logger.info("Client certificates for {} were created by another process. Skipping save.", name);
                    } else {
                        saveClientCertificatesAsSecrets(name, tempDir);
                        logger.info("Successfully generated and saved client cert for: {}", name);
                    }
                } else {
                    logger.error("Failed to generate Nebula client certificate. Exit code: {}. Output: {}", exitCode,
                            output.toString());
                    throw new RuntimeException("Failed to generate Nebula client certificate. Exit code: " + exitCode);
                }

                cleanupTempFiles(tempNebulaCert, tempDir);
            } catch (Exception e) {
                logger.error("Error generating Nebula client certificate for {}", name, e);
                throw new RuntimeException("Failed to generate Nebula client certificate for " + name, e);
            }
        }
    }

    private List<String> buildNebulaCertCommand(Path tempNebulaCert, String name, String ipWithSubnet,
            Set<String> groups, Path tempDir) {
        // Retrieve CA key and cert from secrets
        Pair<Secret, Secret> caKeyAndCert = loadCAKeyAndCert();

        // Write CA key and cert to temporary files
        Path caKeyPath = tempDir.resolve("ca.key");
        Path caCertPath = tempDir.resolve("ca.crt");
        try {
            Files.write(caKeyPath, caKeyAndCert.getFirst().getContent().getBytes());
            Files.write(caCertPath, caKeyAndCert.getSecond().getContent().getBytes());
        } catch (IOException e) {
            throw new RuntimeException("Failed to write CA files", e);
        }

        List<String> command = new ArrayList<>(Arrays.asList(
                tempNebulaCert.toString(),
                "sign",
                "-name", name,
                "-ip", ipWithSubnet,
                "-out-crt", tempDir.resolve(name + ".crt").toString(),
                "-out-key", tempDir.resolve(name + ".key").toString(),
                "-ca-key", caKeyPath.toString(),
                "-ca-crt", caCertPath.toString()));

        if (groups != null && !groups.isEmpty()) {
            command.add("-groups");
            command.add(String.join(",", groups));
        }

        return command;
    }

    private void saveClientCertificatesAsSecrets(String name, Path tempDir) throws IOException {
        Path crtPath = tempDir.resolve(name + ".crt");
        Path keyPath = tempDir.resolve(name + ".key");

        if (Files.exists(crtPath) && Files.exists(keyPath)) {
            String cert = new String(Files.readAllBytes(crtPath));
            String key = new String(Files.readAllBytes(keyPath));

            secretsService.addSecret("nebula_" + name + "_cert", "NEBULA_CLIENT_CERT", cert);
            secretsService.addSecret("nebula_" + name + "_key", "NEBULA_CLIENT_KEY", key);

            logger.info("Nebula client certificates saved as secrets for: {}", name);
        } else {
            logger.error(
                    "Nebula client certificate files not found after generation for: {}. Cert exists: {}, Key exists: {}",
                    name, Files.exists(crtPath), Files.exists(keyPath));
            throw new RuntimeException("Nebula client certificate files not found after generation for: " + name);
        }
    }

    private void cleanupTempFiles(Path tempNebulaCert, Path tempDir) {
        try {
            Files.deleteIfExists(tempNebulaCert);
            Files.walk(tempDir)
                    .sorted((p1, p2) -> -p1.compareTo(p2))
                    .forEach(p -> {
                        try {
                            Files.delete(p);
                        } catch (IOException e) {
                            logger.warn("Failed to delete temporary file: {}", p, e);
                        }
                    });
        } catch (IOException e) {
            logger.warn("Error cleaning up temporary files", e);
        }
    }

    /**
     * Consistently loads both CA key and cert together.
     * This prevents race conditions where one thread gets the key and another gets
     * the cert.
     * 
     * @return A pair of CA key and cert secrets
     * @throws RuntimeException if either the key or cert is missing
     */
    private synchronized Pair<Secret, Secret> loadCAKeyAndCert() {
        Secret caKeySecret = secretsService.getSecretByName("nebula_ca_key")
                .orElseThrow(() -> new RuntimeException("Nebula CA key not found in secrets"));
        Secret caCertSecret = secretsService.getSecretByName("nebula_ca_cert")
                .orElseThrow(() -> new RuntimeException("Nebula CA cert not found in secrets"));
        return new Pair<>(caKeySecret, caCertSecret);
    }

    /**
     * Simple pair class to hold two values.
     */
    private static class Pair<K, V> {
        private final K first;
        private final V second;

        public Pair(K first, V second) {
            this.first = first;
            this.second = second;
        }

        public K getFirst() {
            return first;
        }

        public V getSecond() {
            return second;
        }
    }
}