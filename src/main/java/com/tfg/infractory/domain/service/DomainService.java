package com.tfg.infractory.domain.service;

import java.util.Set;
import java.util.List;
import org.slf4j.Logger;
import java.util.Optional;
import org.slf4j.LoggerFactory;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tfg.infractory.domain.model.Domain;
import com.tfg.infractory.domain.model.Provider;
import com.tfg.infractory.domain.repository.DomainRepository;
import com.tfg.infractory.domain.repository.ProviderRepository;

@Service
public class DomainService {
    private static final Logger logger = LoggerFactory.getLogger(DomainService.class);

    private final DomainRepository domainRepository;
    private final ProviderRepository providerRepository;

    public DomainService(DomainRepository domainRepository, ProviderRepository providerRepository) {
        this.domainRepository = domainRepository;
        this.providerRepository = providerRepository;
    }

    @Transactional
    public void addDomains(List<Domain> domains) {
        Set<Provider> providers = domains.stream()
                .map(Domain::getProvider)
                .collect(Collectors.toSet());

        Set<String> providerNames = providers.stream()
                .map(Provider::getName)
                .collect(Collectors.toSet());

        Set<String> existingProviderNames = providerRepository.findAllById(providerNames)
                .stream()
                .map(Provider::getName)
                .collect(Collectors.toSet());

        Set<Provider> newProviders = providers.stream()
                .filter(provider -> !existingProviderNames.contains(provider.getName()))
                .collect(Collectors.toSet());

        if (!newProviders.isEmpty()) {
            providerRepository.saveAll(newProviders);
            logger.info("Saved {} new providers", newProviders.size());
        }

        Set<String> domainNames = domains.stream()
                .map(Domain::getDomain)
                .collect(Collectors.toSet());

        Set<String> existingDomainNames = domainRepository.findAllByDomainIn(domainNames)
                .stream()
                .map(Domain::getDomain)
                .collect(Collectors.toSet());

        List<Domain> newDomains = domains.stream()
                .filter(domain -> !existingDomainNames.contains(domain.getDomain()))
                .collect(Collectors.toList());

        if (!newDomains.isEmpty()) {
            domainRepository.saveAll(newDomains);
            logger.info("Saved {} new domains", newDomains.size());
        }

        Set<Domain> uniqueDomains = Set.copyOf(domains);
        if (uniqueDomains.size() < domains.size()) {
            logger.warn("Duplicate domains detected in the input");
            throw new IllegalArgumentException("Duplicate domains are not allowed");
        }
    }

    public Domain getDomain(Long id) {
        return domainRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Domain not found: " + id));
    }

    @Transactional
    public Domain createDomain(Domain domain) {
        if (!providerRepository.existsById(domain.getProvider().getName())) {
            logger.error("Provider does not exist: {}", domain.getProvider().getName());
            throw new IllegalArgumentException("Provider does not exist: " + domain.getProvider().getName());
        }
        return domainRepository.save(domain);
    }

    @Transactional
    public Domain updateDomain(Long id, Domain domainDetails) {
        Domain domain = getDomain(id);
        domain.setDomain(domainDetails.getDomain());
        domain.setProvider(domainDetails.getProvider());
        return domainRepository.save(domain);
    }

    @Transactional
    public void deleteDomain(Long id) {
        Domain domain = getDomain(id);
        domainRepository.delete(domain);
    }

    public List<Domain> getAllDomains() {
        return domainRepository.findAll();
    }

    public Optional<Domain> getDomainByDomain(String domainName) {
        return domainRepository.findDomainByDomain(domainName);
    }
}
