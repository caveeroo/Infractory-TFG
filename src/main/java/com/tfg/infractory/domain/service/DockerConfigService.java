package com.tfg.infractory.domain.service;

import java.util.List;
import java.util.Map;
import java.util.HashMap;
import org.springframework.stereotype.Service;
import org.springframework.context.annotation.Lazy;
import com.github.dockerjava.api.model.ServiceSpec;
import org.springframework.beans.factory.annotation.Autowired;

import com.tfg.infractory.domain.model.DockerConfig;
import com.tfg.infractory.domain.repository.DockerConfigRepository;
import com.tfg.infractory.infrastructure.docker.service.DockerSwarmService;

@Service
public class DockerConfigService {

    @Autowired
    private DockerConfigRepository dockerConfigRepository;

    @Autowired
    @Lazy
    private DockerSwarmService dockerSwarmService;

    public DockerConfig createDockerConfig(DockerConfig dockerConfig) {
        return dockerConfigRepository.save(dockerConfig);
    }

    public List<DockerConfig> getAllDockerConfigs() {
        return dockerConfigRepository.findAll();
    }

    public DockerConfig getDockerConfigById(Long id) {
        return dockerConfigRepository.findById(id).orElse(null);
    }

    public void updateDockerConfig(Long id, DockerConfig updatedConfig) {
        DockerConfig existingConfig = getDockerConfigById(id);
        if (existingConfig != null) {
            existingConfig.setName(updatedConfig.getName());
            existingConfig.setContent(updatedConfig.getContent());
            dockerConfigRepository.save(existingConfig);
        }
    }

    public void deleteDockerConfig(Long id) {
        dockerConfigRepository.deleteById(id);
    }

    public void applyConfigToSwarm(DockerConfig config) {
        try {
            ServiceSpec serviceSpec = createServiceSpec(config);
            Map<String, String> placementConstraints = createPlacementConstraints(config);
            dockerSwarmService.createService(serviceSpec, placementConstraints);
        } catch (Exception e) {
            // Handle any exceptions
        }
    }

    private ServiceSpec createServiceSpec(DockerConfig config) {
        // Implement the logic to create a ServiceSpec from the DockerConfig
        // This will depend on the structure of your DockerConfig and what you want to
        // deploy
        return null;
    }

    private Map<String, String> createPlacementConstraints(DockerConfig config) {
        // Implement the logic to create placement constraints from the DockerConfig
        // This will depend on how you want to define and store placement constraints in
        // your DockerConfig
        Map<String, String> constraints = new HashMap<>();
        // Example: constraints.put("node.labels.type", "worker");
        return constraints;
    }
}