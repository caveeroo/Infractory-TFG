package com.tfg.infractory.domain.service;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tfg.infractory.domain.model.*;

@Service
public class InitializationService {

    private static final Logger logger = LoggerFactory.getLogger(InitializationService.class);

    private final ProviderService providerService;
    private final DomainService domainService;

    public InitializationService(ProviderService providerService,
            DomainService domainService) {
        this.providerService = providerService;
        this.domainService = domainService;
    }

    @Transactional
    public void initializeData() {
        try {
            // Check if data already exists in the database
            List<Provider> existingProviders = providerService.getAllProviders();
            if (!existingProviders.isEmpty()) {
                logger.info("Database already contains data. Skipping initialization.");
                return;
            }

            logger.info("Database is empty. Starting initialization...");
            initializeProviders();
            initializeDomains();
            initializeDockerConfigs();
            logger.info("Database initialization completed successfully.");
        } catch (Exception e) {
            logger.error("Error initializing data", e);
        }
    }

    private void initializeProviders() {
        List<String> providerNames = List.of("NameCheap", "AWS", "Azure", "GCP", "Cloudflare", "Local");
        for (String name : providerNames) {
            initializeProvider(name);
        }
    }

    private void initializeDomains() {
        initializeDomain("test.com", "AWS");
        initializeDomain("test2.com", "AWS");
        initializeDomain("phishing.com", "NameCheap");
        initializeDomain("legit-gmail.com", "Cloudflare");
        initializeDomain("teamserver.com", "NameCheap");
        initializeDomain("legit-ts.com", "NameCheap");
    }

    private void initializeDockerConfigs() {
        logger.info("Initialized default Docker image and config");
    }

    private Provider initializeProvider(String name) {
        Provider provider = providerService.getProvider(name);
        if (provider == null) {
            provider = providerService.createProvider(new Provider(name));
            logger.info("Created new provider: {}", name);
        }
        return provider;
    }

    private Domain initializeDomain(String domainName, String providerName) {
        Domain domain = domainService.getDomainByDomain(domainName).orElse(null);
        if (domain == null) {
            Provider provider = providerService.getProvider(providerName);
            domain = domainService.createDomain(new Domain(domainName, provider));
            logger.info("Created new domain: {} for provider: {}", domainName, providerName);
        }
        return domain;
    }
}
