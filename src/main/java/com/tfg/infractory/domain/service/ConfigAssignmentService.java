package com.tfg.infractory.domain.service;

import com.tfg.infractory.domain.model.ConfigAssignment;
import com.tfg.infractory.domain.model.ConfigAssignment.TargetType;
import com.tfg.infractory.domain.model.DockerConfig;
import com.tfg.infractory.domain.model.Instance;
import com.tfg.infractory.domain.model.Server;
import com.tfg.infractory.domain.repository.ConfigAssignmentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Service for managing assignments of Docker configurations to server types or
 * instances
 */
@Service
public class ConfigAssignmentService {

    @Autowired
    private ConfigAssignmentRepository configAssignmentRepository;

    /**
     * Assign a Docker configuration to a server type
     * 
     * @param dockerConfig The Docker configuration to assign
     * @param serverType   The type of server to target (e.g., "Redirector",
     *                     "TeamServer")
     * @return The created assignment
     */
    @Transactional
    public ConfigAssignment assignToServerType(DockerConfig dockerConfig, String serverType) {
        ConfigAssignment assignment = new ConfigAssignment();
        assignment.setDockerConfig(dockerConfig);
        assignment.setTargetType(TargetType.SERVER_TYPE);
        assignment.setServerType(serverType);
        return configAssignmentRepository.save(assignment);
    }

    /**
     * Assign a Docker configuration to a specific instance
     * 
     * @param dockerConfig The Docker configuration to assign
     * @param instance     The specific instance to target
     * @return The created assignment
     */
    @Transactional
    public ConfigAssignment assignToInstance(DockerConfig dockerConfig, Instance instance) {
        ConfigAssignment assignment = new ConfigAssignment();
        assignment.setDockerConfig(dockerConfig);
        assignment.setTargetType(TargetType.INSTANCE_SPECIFIC);
        assignment.setInstance(instance);
        return configAssignmentRepository.save(assignment);
    }

    /**
     * Get all Docker configurations that should be applied to a server,
     * including both server-type configurations and instance-specific
     * configurations
     * 
     * @param server The server to get configurations for
     * @return List of Docker configurations
     */
    public List<DockerConfig> getConfigsForServer(Server server) {
        // Get the server's type from its class name
        String serverType = server.getClass().getSimpleName();

        // Find configs assigned to this server type
        List<ConfigAssignment> serverTypeAssignments = configAssignmentRepository
                .findByTargetTypeAndServerType(TargetType.SERVER_TYPE, serverType);

        // Find configs assigned to this specific instance
        List<ConfigAssignment> instanceAssignments = configAssignmentRepository
                .findByTargetTypeAndInstance(TargetType.INSTANCE_SPECIFIC, server.getInstance());

        // Combine both lists of assignments
        List<ConfigAssignment> allAssignments = new ArrayList<>(serverTypeAssignments);
        allAssignments.addAll(instanceAssignments);

        // Extract and return all the Docker configs
        return allAssignments.stream()
                .map(ConfigAssignment::getDockerConfig)
                .distinct() // Remove duplicates if any
                .collect(Collectors.toList());
    }

    /**
     * Get all assignments for a Docker configuration
     * 
     * @param dockerConfig The Docker configuration
     * @return List of assignments for this configuration
     */
    public List<ConfigAssignment> getAssignmentsForConfig(DockerConfig dockerConfig) {
        return configAssignmentRepository.findByDockerConfigId(dockerConfig.getId());
    }

    /**
     * Delete an assignment
     * 
     * @param id The ID of the assignment to delete
     */
    @Transactional
    public void deleteAssignment(Long id) {
        configAssignmentRepository.deleteById(id);
    }
}