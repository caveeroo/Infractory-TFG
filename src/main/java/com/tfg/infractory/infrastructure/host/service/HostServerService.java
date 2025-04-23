package com.tfg.infractory.infrastructure.host.service;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tfg.infractory.domain.model.DockerConfig;
import com.tfg.infractory.domain.model.HostServer;
import com.tfg.infractory.domain.repository.HostServerRepository;
import com.tfg.infractory.domain.repository.ServerRepository;
import com.tfg.infractory.infrastructure.cloud.model.Details;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;
import com.tfg.infractory.infrastructure.docker.service.DockerSwarmService;
import com.tfg.infractory.infrastructure.nebula.service.NebulaService;
import com.tfg.infractory.web.dto.NebulaConfigurationDTO;

/**
 * Service for managing the host machine as a server in the infrastructure.
 * This allows the host to be integrated into the Nebula network and serve
 * as the Docker Swarm manager.
 */
@Service("infrastructureHostServerService")
public class HostServerService {

    private static final Logger logger = LoggerFactory.getLogger(HostServerService.class);

    private final HostServerRepository hostServerRepository;
    private final NebulaService nebulaService;
    private final DockerSwarmService dockerSwarmService;

    @Autowired
    public HostServerService(
            ServerRepository serverRepository,
            HostServerRepository hostServerRepository,
            NebulaService nebulaService,
            DockerSwarmService dockerSwarmService,
            ApplicationEventPublisher eventPublisher) {
        this.hostServerRepository = hostServerRepository;
        this.nebulaService = nebulaService;
        this.dockerSwarmService = dockerSwarmService;
    }

    /**
     * Creates a HostServer representing the host machine and integrates it
     * into the Nebula network.
     * 
     * @param lighthouseNebulaId The ID of the lighthouse Nebula configuration
     * @return The created HostServer
     */
    @Transactional
    public HostServer createHostServer(Long lighthouseNebulaId) {
        logger.info("Creating HostServer with lighthouse Nebula ID: {}", lighthouseNebulaId);

        // Check if a host server already exists
        HostServer existingHost = findHostServer();
        if (existingHost != null) {
            logger.info("HostServer already exists with ID: {}", existingHost.getId());
            return existingHost;
        }

        // Create Nebula configuration for the host
        NebulaConfigurationDTO nebulaConfig = new NebulaConfigurationDTO();
        nebulaConfig.setLighthouse(false);
        nebulaConfig.setLighthouseId(lighthouseNebulaId);
        nebulaConfig.setRoles(Set.of("host", "swarm-manager"));
        nebulaConfig.setAllowedRoles(Set.of("lighthouse", "swarm-worker"));

        Nebula hostNebula = nebulaService.createNebulaConfig(nebulaConfig);
        logger.info("Created Nebula configuration for host with ID: {}", hostNebula.getId());

        // Create details for the host
        Details hostDetails = new Details();
        hostDetails.setName("Host Machine");
        hostDetails.setDescription("Physical host machine running the infrastructure");

        // Create a basic Docker configuration
        DockerConfig dockerConfig = new DockerConfig();
        dockerConfig.setName("host-docker-config");

        try {
            // Create the HostServer with hostname
            String hostname = InetAddress.getLocalHost().getHostName();
            HostServer hostServer = new HostServer(hostname);
            hostServer.setVpn(hostNebula);

            // Save the host server
            HostServer savedHostServer = hostServerRepository.save(hostServer);
            logger.info("Created HostServer with ID: {}", savedHostServer.getId());

            // Initialize Docker Swarm on the host
            String initResult = dockerSwarmService.initializeSwarmOnHost();
            logger.info("Docker Swarm initialization result: {}", initResult);

            return savedHostServer;
        } catch (UnknownHostException e) {
            logger.error("Failed to get local hostname", e);
            HostServer hostServer = new HostServer("host-machine");
            hostServer.setVpn(hostNebula);

            HostServer savedHostServer = hostServerRepository.save(hostServer);
            logger.info("Created HostServer with ID: {}", savedHostServer.getId());

            return savedHostServer;
        }
    }

    /**
     * Finds the existing HostServer if one exists.
     * 
     * @return The existing HostServer or null if none exists
     */
    @Transactional(readOnly = true)
    public HostServer findHostServer() {
        return hostServerRepository.findFirstByOrderByIdAsc().orElse(null);
    }

    /**
     * Gets the Nebula IP of the host machine.
     * 
     * @return The Nebula IP of the host or null if not configured
     */
    public String getHostNebulaIp() {
        HostServer hostServer = findHostServer();
        if (hostServer != null && hostServer.getVpn() != null) {
            return hostServer.getVpn().getIp();
        }
        return null;
    }
}