package com.tfg.infractory.domain.service;

import java.util.Map;
import java.util.List;
import org.slf4j.Logger;
import java.net.InetAddress;
import org.slf4j.LoggerFactory;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.scheduling.annotation.EnableScheduling;

import com.tfg.infractory.domain.exception.InstanceNotFoundException;
import com.tfg.infractory.domain.model.Instance;
import com.tfg.infractory.domain.repository.InstanceRepository;
import com.tfg.infractory.infrastructure.cloud.service.CloudProviderService;

@Service
@EnableScheduling
public class InstanceIPUpdateService {

    private static final Logger logger = LoggerFactory.getLogger(InstanceIPUpdateService.class);

    private final InstanceRepository instanceRepository;
    private final Map<String, CloudProviderService> cloudProviderServiceMap;

    public InstanceIPUpdateService(InstanceRepository instanceRepository,
            List<CloudProviderService> cloudProviderServices) {
        this.instanceRepository = instanceRepository;
        this.cloudProviderServiceMap = cloudProviderServices.stream()
                .collect(Collectors.toMap(
                        service -> service.getClass().getSimpleName().replace("CloudProviderService", ""),
                        Function.identity()));
    }

    @Scheduled(fixedDelay = 30000) // Run every 30 seconds
    @Transactional
    public void updateInstanceIPs() {
        // logger.info("Starting instance IP update process");
        List<Instance> instances = instanceRepository.findAll();
        for (Instance instance : instances) {
            updateInstanceStatus(instance);
        }
        // logger.info("Finished instance IP update process");
    }

    private void updateInstanceStatus(Instance instance) {
        CloudProviderService service = cloudProviderServiceMap.get(instance.getProvider().getName());
        if (service == null) {
            logger.warn("No service found for provider: {}", instance.getProvider().getName());
            return;
        }

        try {
            logger.debug("Updating status for instance {}", instance.getId());
            InetAddress ip = service.getInstanceIp(instance.getProviderId());
            Instance.InstanceStatus status = service.getInstanceStatus(instance.getProviderId());

            if (ip != null && !ip.isLoopbackAddress()) {
                instance.setIp(ip);
                instance.setStatus(status);
            } else if (instance.getStatus() == Instance.InstanceStatus.CREATING) {
                // If still creating, don't change the status
                return;
            } else {
                instance.setStatus(Instance.InstanceStatus.STOPPED);
            }

            instanceRepository.save(instance);
            logger.debug("Updated status for instance {}: {}", instance.getId(), instance.getStatus());
        } catch (InstanceNotFoundException e) {
            instance.setStatus(Instance.InstanceStatus.DELETED);
            instanceRepository.save(instance);
            logger.warn("Instance {} not found, marked as DELETED", instance.getId());
        } catch (Exception e) {
            if (instance.getStatus() != Instance.InstanceStatus.CREATING) {
                instance.setStatus(Instance.InstanceStatus.ERROR);
                instanceRepository.save(instance);
            }
            logger.error("Error updating instance " + instance.getId() + ": " + e.getMessage(), e);
        }
    }
}