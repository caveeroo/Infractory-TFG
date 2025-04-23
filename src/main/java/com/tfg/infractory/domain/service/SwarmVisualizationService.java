package com.tfg.infractory.domain.service;

import com.tfg.infractory.domain.model.SwarmNode;
import com.tfg.infractory.domain.model.SwarmService;
import com.tfg.infractory.domain.model.Server;
import com.tfg.infractory.domain.repository.SwarmNodeRepository;
import com.tfg.infractory.domain.repository.SwarmServiceRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Service for visualizing and querying the Docker Swarm
 */
@Service
public class SwarmVisualizationService {

    @Autowired
    private SwarmNodeRepository swarmNodeRepository;

    @Autowired
    private SwarmServiceRepository swarmServiceRepository;

    /**
     * Get all nodes in the swarm
     */
    public List<SwarmNode> getAllNodes() {
        return swarmNodeRepository.findAll();
    }

    /**
     * Get a specific node by ID
     */
    public SwarmNode getNodeById(Long id) {
        return swarmNodeRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Node not found with ID: " + id));
    }

    /**
     * Get all manager nodes
     */
    public List<SwarmNode> getManagerNodes() {
        return swarmNodeRepository.findByRole("manager");
    }

    /**
     * Get all worker nodes
     */
    public List<SwarmNode> getWorkerNodes() {
        return swarmNodeRepository.findByRole("worker");
    }

    /**
     * Get all nodes with a specific status
     */
    public List<SwarmNode> getNodesByStatus(String status) {
        return swarmNodeRepository.findByStatus(status);
    }

    /**
     * Get the node associated with a specific server
     */
    public Optional<SwarmNode> getNodeForServer(Server server) {
        return swarmNodeRepository.findByServer(server);
    }

    /**
     * Get all services in the swarm
     */
    public List<SwarmService> getAllServices() {
        return swarmServiceRepository.findAll();
    }

    /**
     * Get a specific service by ID
     */
    public SwarmService getServiceById(Long id) {
        return swarmServiceRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Service not found with ID: " + id));
    }

    /**
     * Get all services running on a specific node
     */
    public List<SwarmService> getServicesForNode(SwarmNode node) {
        return swarmServiceRepository.findByNode(node);
    }

    /**
     * Get all services with a specific tag
     */
    public List<SwarmService> getServicesByTag(String tag) {
        return swarmServiceRepository.findByTag(tag);
    }

    /**
     * Get all services that have all of the specified tags
     */
    public List<SwarmService> getServicesByAllTags(Set<String> tags) {
        return swarmServiceRepository.findByAllTags(tags, (long) tags.size());
    }

    /**
     * Get all nodes that have services with a specific tag
     */
    public List<SwarmNode> getNodesByServiceTag(String tag) {
        List<SwarmService> services = swarmServiceRepository.findByTag(tag);
        return services.stream()
                .map(SwarmService::getNode)
                .distinct()
                .collect(Collectors.toList());
    }

    /**
     * Get all nodes of a specific server type
     */
    public List<SwarmNode> getNodesByServerType(String serverType) {
        return swarmNodeRepository.findAll().stream()
                .filter(node -> node.getServer() != null &&
                        node.getServer().getClass().getSimpleName().equals(serverType))
                .collect(Collectors.toList());
    }
}