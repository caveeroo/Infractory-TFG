package com.tfg.infractory.domain.model;

import lombok.Data;
import jakarta.persistence.*;

/**
 * Represents the assignment of a DockerConfig to either a server type
 * (all servers of a certain type) or to a specific instance.
 */
@Entity
@Data
public class ConfigAssignment {
    @Id
    @GeneratedValue
    private Long id;

    /**
     * The Docker configuration that is being assigned
     */
    @ManyToOne
    private DockerConfig dockerConfig;

    /**
     * The type of targeting for this assignment
     */
    @Enumerated(EnumType.STRING)
    private TargetType targetType;

    /**
     * The server type this config is assigned to (when targetType = SERVER_TYPE)
     */
    private String serverType;

    /**
     * The specific instance this config is assigned to (when targetType =
     * INSTANCE_SPECIFIC)
     */
    @ManyToOne
    private Instance instance;

    /**
     * Targeting strategy for Docker configurations
     */
    public enum TargetType {
        /**
         * Target all servers of a specific type (Redirector, TeamServer, etc.)
         */
        SERVER_TYPE,

        /**
         * Target a specific instance
         */
        INSTANCE_SPECIFIC
    }
}