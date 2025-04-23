package com.tfg.infractory.domain.model;

import lombok.Data;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Represents a service running in the Docker Swarm
 */
@Entity
@Data
public class SwarmService {
    @Id
    @GeneratedValue
    private Long id;

    /**
     * Docker service ID
     */
    private String serviceId;

    /**
     * Service name
     */
    private String serviceName;

    /**
     * Service status (running, stopped, etc.)
     */
    private String status;

    /**
     * The Docker image used by this service
     */
    @ManyToOne
    @JoinColumn(name = "image_id")
    private DockerImage dockerImage;

    /**
     * The node this service is running on
     */
    @ManyToOne
    @JoinColumn(name = "node_id")
    private SwarmNode node;

    /**
     * Environment variables for this service
     */
    @ElementCollection
    @CollectionTable(name = "swarm_service_env_vars", joinColumns = @JoinColumn(name = "service_id"))
    @MapKeyColumn(name = "env_key")
    @Column(name = "env_value")
    private Map<String, String> environmentVariables = new HashMap<>();

    /**
     * Tags for filtering and targeting
     */
    @ElementCollection
    @CollectionTable(name = "swarm_service_tags", joinColumns = @JoinColumn(name = "service_id"))
    @Column(name = "tag")
    private Set<String> tags = new HashSet<>();

    /**
     * Creation timestamp
     */
    @Column(name = "created_at")
    private LocalDateTime createdAt;

    /**
     * Last update timestamp
     */
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    /**
     * Placement constraints for this service
     */
    @ElementCollection
    @CollectionTable(name = "swarm_service_placement_constraints", joinColumns = @JoinColumn(name = "service_id"))
    @MapKeyColumn(name = "constraint_key")
    @Column(name = "constraint_value")
    private Map<String, String> placementConstraints = new HashMap<>();

    /**
     * Number of replicas for this service
     */
    private int replicas = 1;

    /**
     * Published ports (comma-separated string of published:target:protocol:mode)
     */
    @Column(name = "published_ports", length = 1024)
    private String publishedPorts;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}