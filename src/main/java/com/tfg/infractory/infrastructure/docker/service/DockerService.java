package com.tfg.infractory.infrastructure.docker.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.context.ApplicationEventPublisher;

import com.tfg.infractory.domain.model.DockerConfig;
import com.tfg.infractory.domain.model.Server;
import com.tfg.infractory.domain.service.ConfigAssignmentService;
import com.tfg.infractory.web.event.ApplyDockerConfigEvent;

import java.util.List;

@Service
public class DockerService {

    private static final Logger logger = LoggerFactory.getLogger(DockerService.class);

    private final ApplicationEventPublisher eventPublisher;
    private final ConfigAssignmentService configAssignmentService;

    public DockerService(ApplicationEventPublisher eventPublisher,
            ConfigAssignmentService configAssignmentService) {
        this.eventPublisher = eventPublisher;
        this.configAssignmentService = configAssignmentService;
    }

    /**
     * Apply Docker configuration to a server based on assigned configurations
     * This includes both server-type configs and instance-specific configs
     */
    public void applyDockerConfigs(Server server) {
        List<DockerConfig> configs = configAssignmentService.getConfigsForServer(server);

        if (!configs.isEmpty()) {
            for (DockerConfig config : configs) {
                logger.info("Publishing ApplyDockerConfigEvent for server {} with config {}",
                        server.getId(), config.getName());

                // Set the config on the server (temporarily) for the event
                server.setDockerConfig(config);
                eventPublisher.publishEvent(new ApplyDockerConfigEvent(this, server));
            }
        } else {
            logger.warn("No Docker configs found for server {}", server.getId());
        }
    }

    public String getContainerStatus(Server server) {
        // This method can remain as is, or you can also use an event-based approach if
        // needed
        // For now, we'll keep it simple
        return "Unknown";
    }
}