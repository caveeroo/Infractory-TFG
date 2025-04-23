package com.tfg.infractory.domain.service;

import java.util.Map;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.stream.Collectors;
import java.util.function.Function;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import com.tfg.infractory.domain.model.Instance;
import com.tfg.infractory.infrastructure.ssh.model.SSHKey;
import com.tfg.infractory.domain.repository.InstanceRepository;
import com.tfg.infractory.infrastructure.ssh.service.SSHKeyService;
import com.tfg.infractory.infrastructure.cloud.service.CloudProviderService;

@Service
public class InstanceService {
    private static final Logger logger = LoggerFactory.getLogger(InstanceService.class);
    private final InstanceRepository instanceRepository;
    private final Map<String, CloudProviderService> cloudProviderServices;
    private final SSHKeyService sshKeyService;

    @Autowired
    public InstanceService(InstanceRepository instanceRepository,
            List<CloudProviderService> cloudProviderServices,
            SSHKeyService sshKeyService) {
        this.instanceRepository = instanceRepository;
        this.cloudProviderServices = cloudProviderServices.stream()
                .collect(Collectors.toMap(
                        this::getProviderName,
                        Function.identity()));
        this.sshKeyService = sshKeyService;

        logger.info("Initialized cloud provider services: {}", this.cloudProviderServices.keySet());
    }

    private String getProviderName(CloudProviderService service) {
        String simpleName = service.getClass().getSimpleName();
        return simpleName.equals("LocalProviderService") ? "Local"
                : simpleName.replace("CloudProviderService", "").replace("ProviderService", "");
    }

    @Transactional
    public void addInstances(List<Instance> instances) {
        for (Instance instance : instances) {
            try {
                instanceRepository.save(instance);
            } catch (Exception e) {
                logger.error("Failed to save instance: " + instance.getName(), e);
            }
        }
    }

    public Instance getInstance(Long id) {
        return instanceRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Instance not found: " + id));
    }

    @Transactional
    public Instance createInstance(String providerName, String name, String imageId, String size, String region,
            Long sshKeyId) {
        logger.info("Attempting to create instance with provider: {}", providerName);
        logger.info("Available providers: {}", cloudProviderServices.keySet());

        CloudProviderService cloudProviderService = cloudProviderServices.get(providerName);
        if (cloudProviderService == null) {
            logger.error("Unsupported cloud provider: {}. Available providers: {}", providerName,
                    cloudProviderServices.keySet());
            throw new IllegalArgumentException("Unsupported cloud provider: " + providerName);
        }

        try {
            SSHKey sshKey = sshKeyId != null ? sshKeyService.getSSHKeyById(sshKeyId) : null;
            if (sshKeyId != null && sshKey == null) {
                logger.warn("SSH key with id {} not found", sshKeyId);
            }

            Instance instance = cloudProviderService.createInstance(name, imageId, size, region, sshKey);
            if (instance == null) {
                logger.error("Failed to create instance with provider: {}", providerName);
                throw new RuntimeException("Failed to create instance with provider: " + providerName);
            }

            // Only set status to CREATING if it hasn't been set by the provider
            if (instance.getStatus() == null) {
                instance.setStatus(Instance.InstanceStatus.CREATING);
            }
            Instance savedInstance = instanceRepository.save(instance);

            // Note: JoinSwarmEvent will be published after Nebula is configured
            logger.info("Instance created successfully. Swarm joining will be handled after Nebula configuration.");

            return savedInstance;
        } catch (Exception e) {
            logger.error("Error creating instance: {}", e.getMessage(), e);
            throw new RuntimeException("Error creating instance", e);
        }
    }

    @Transactional
    public Instance updateInstance(Long id, Instance instanceDetails) {
        Instance instance = getInstance(id);
        instance.setProvider(instanceDetails.getProvider());
        instance.setRegion(instanceDetails.getRegion());
        instance.setIp(instanceDetails.getIp());
        instance.setCreated(instanceDetails.getCreated());
        instance.setDestroyed(instanceDetails.getDestroyed());
        return instanceRepository.save(instance);
    }

    @Transactional
    public void deleteInstance(Long id) {
        Instance instance = getInstance(id);
        instanceRepository.delete(instance);
    }

    public List<Instance> getAllInstances() {
        return instanceRepository.findAll();
    }

    public boolean isProviderConfigured(String providerName) {
        CloudProviderService cloudProviderService = cloudProviderServices.get(providerName);
        return cloudProviderService != null && cloudProviderService.isConfigured();
    }
}