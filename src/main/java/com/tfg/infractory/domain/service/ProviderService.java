package com.tfg.infractory.domain.service;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tfg.infractory.domain.model.Provider;
import com.tfg.infractory.domain.repository.ProviderRepository;

@Service
public class ProviderService {
    private static final Logger logger = LoggerFactory.getLogger(ProviderService.class);

    private final ProviderRepository providerRepository;

    public ProviderService(ProviderRepository providerRepository) {
        this.providerRepository = providerRepository;
    }

    public Provider getProvider(String name) {
        return providerRepository.findById(name).orElse(null);
    }

    @Transactional
    public Provider createProvider(Provider provider) {
        if (providerRepository.existsById(provider.getName())) {
            logger.warn("Provider already exists: {}", provider.getName());
            throw new IllegalArgumentException("Provider already exists: " + provider.getName());
        }
        Provider savedProvider = providerRepository.save(provider);
        logger.info("Created new provider: {}", savedProvider.getName());
        return savedProvider;
    }

    @Transactional
    public Provider updateProvider(String name, Provider providerDetails) {
        Provider provider = getProvider(name);
        if (provider == null) {
            logger.warn("Provider does not exist: {}", name);
            throw new IllegalArgumentException("Provider does not exist: " + name);
        }
        provider.setName(providerDetails.getName());
        Provider updatedProvider = providerRepository.save(provider);
        logger.info("Updated provider: {}", updatedProvider.getName());
        return updatedProvider;
    }

    @Transactional
    public void deleteProvider(String name) {
        Provider provider = getProvider(name);
        if (provider != null) {
            providerRepository.delete(provider);
            logger.info("Deleted provider: {}", name);
        } else {
            logger.warn("Attempted to delete non-existent provider: {}", name);
        }
    }

    public List<Provider> getAllProviders() {
        return providerRepository.findAll();
    }
}
