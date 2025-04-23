package com.tfg.infractory.domain.service;

import java.util.Optional;
import java.util.UUID;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tfg.infractory.domain.model.HostServer;
import com.tfg.infractory.domain.repository.HostServerRepository;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;

/**
 * Service for managing the host server entity.
 * This service provides methods for creating, finding, and managing the host
 * machine
 * as a server in the system.
 */
@Service
public class HostServerService {

    private static final Logger logger = LoggerFactory.getLogger(HostServerService.class);

    private final HostServerRepository hostServerRepository;

    @Autowired
    public HostServerService(HostServerRepository hostServerRepository) {
        this.hostServerRepository = hostServerRepository;
    }

    /**
     * Creates a new host server entity with the local hostname.
     * 
     * @return The created host server entity
     */
    @Transactional
    public HostServer createHostServer() {
        try {
            String hostname = InetAddress.getLocalHost().getHostName();
            HostServer hostServer = new HostServer(hostname);
            return hostServerRepository.save(hostServer);
        } catch (UnknownHostException e) {
            logger.error("Failed to get local hostname", e);
            HostServer hostServer = new HostServer("host-machine");
            return hostServerRepository.save(hostServer);
        }
    }

    /**
     * Finds a host server by its ID.
     * 
     * @param id The ID of the host server
     * @return An Optional containing the host server if found, empty otherwise
     */
    @Transactional(readOnly = true)
    public Optional<HostServer> findById(UUID id) {
        return hostServerRepository.findById(id);
    }

    /**
     * Finds the first host server in the system.
     * This is useful when there should only be one host server.
     * 
     * @return An Optional containing the host server if found, empty otherwise
     */
    @Transactional(readOnly = true)
    public Optional<HostServer> findFirst() {
        return hostServerRepository.findFirstByOrderByIdAsc();
    }

    /**
     * Saves a host server entity.
     * 
     * @param hostServer The host server entity to save
     * @return The saved host server entity
     */
    @Transactional
    public HostServer save(HostServer hostServer) {
        return hostServerRepository.save(hostServer);
    }

    /**
     * Sets the Nebula configuration for a host server.
     * 
     * @param hostServer The host server entity
     * @param nebula     The Nebula configuration
     * @return The updated host server entity
     */
    @Transactional
    public HostServer setNebulaConfig(HostServer hostServer, Nebula nebula) {
        hostServer.setVpn(nebula);
        return hostServerRepository.save(hostServer);
    }

    /**
     * Marks a host server as having Nebula deployed.
     * 
     * @param hostServer The host server entity
     * @return The updated host server entity
     */
    @Transactional
    public HostServer markNebulaDeployed(HostServer hostServer) {
        hostServer.setNebulaDeployed(true);
        return hostServerRepository.save(hostServer);
    }

    /**
     * Marks a host server as a swarm manager.
     * 
     * @param hostServer The host server entity
     * @return The updated host server entity
     */
    @Transactional
    public HostServer markAsSwarmManager(HostServer hostServer) {
        hostServer.setSwarmManager(true);
        return hostServerRepository.save(hostServer);
    }
}