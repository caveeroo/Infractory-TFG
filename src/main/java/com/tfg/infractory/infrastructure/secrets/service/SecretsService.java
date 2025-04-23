package com.tfg.infractory.infrastructure.secrets.service;

import com.tfg.infractory.infrastructure.secrets.model.Secret;
import com.tfg.infractory.infrastructure.secrets.repository.SecretsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.tfg.infractory.common.security.EncryptionService;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class SecretsService {

    @Autowired
    private SecretsRepository secretsRepository;

    @Autowired
    private EncryptionService encryptionService;

    public void addSecret(String name, String type, String content) {
        Secret secret = new Secret();
        secret.setName(name);
        secret.setType(type);
        secret.setContent(encryptionService.encrypt(content));
        secretsRepository.save(secret);
    }

    public Optional<Secret> getSecretByName(String name) {
        List<Secret> secrets = secretsRepository.findByName(name);
        if (secrets.isEmpty()) {
            return Optional.empty();
        }
        Secret originalSecret = secrets.get(0);

        String decryptedContent;
        try {
            decryptedContent = encryptionService.decrypt(originalSecret.getContent());
        } catch (Exception e) {
            System.err.println("Failed to decrypt secret content for name '" + name + "': " + e.getMessage());
            return Optional.empty();
        }

        Secret decryptedSecretView = new Secret();
        decryptedSecretView.setId(originalSecret.getId());
        decryptedSecretView.setName(originalSecret.getName());
        decryptedSecretView.setType(originalSecret.getType());
        decryptedSecretView.setContent(decryptedContent);
        return Optional.of(decryptedSecretView);
    }

    public List<Secret> getAllSecretsByName(String name) {
        List<Secret> originalSecrets = secretsRepository.findByName(name);
        return originalSecrets.stream()
                .map(originalSecret -> {
                    String decryptedContent = "";
                    try {
                        decryptedContent = encryptionService.decrypt(originalSecret.getContent());
                    } catch (Exception e) {
                        System.err.println("Failed to decrypt secret content for name '" + originalSecret.getName()
                                + "' (ID: " + originalSecret.getId() + "): " + e.getMessage());
                    }
                    Secret decryptedSecretView = new Secret();
                    decryptedSecretView.setId(originalSecret.getId());
                    decryptedSecretView.setName(originalSecret.getName());
                    decryptedSecretView.setType(originalSecret.getType());
                    decryptedSecretView.setContent(decryptedContent);
                    return decryptedSecretView;
                })
                .collect(Collectors.toList());
    }

    public List<Secret> getAllSecrets() {
        List<Secret> originalSecrets = secretsRepository.findAll();
        return originalSecrets.stream()
                .map(originalSecret -> {
                    String decryptedContent = "";
                    try {
                        decryptedContent = encryptionService.decrypt(originalSecret.getContent());
                    } catch (Exception e) {
                        System.err.println("Failed to decrypt secret content for name '" + originalSecret.getName()
                                + "' (ID: " + originalSecret.getId() + "): " + e.getMessage());
                    }
                    Secret decryptedSecretView = new Secret();
                    decryptedSecretView.setId(originalSecret.getId());
                    decryptedSecretView.setName(originalSecret.getName());
                    decryptedSecretView.setType(originalSecret.getType());
                    decryptedSecretView.setContent(decryptedContent);
                    return decryptedSecretView;
                })
                .collect(Collectors.toList());
    }

    public void deleteSecret(Long id) {
        secretsRepository.deleteById(id);
    }

    public void deleteSecretByName(String name) {
        List<Secret> secrets = secretsRepository.findByName(name);
        if (!secrets.isEmpty()) {
            secretsRepository.deleteAll(secrets);
        }
    }
}
