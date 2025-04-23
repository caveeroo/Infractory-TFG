package com.tfg.infractory.domain.model;

import lombok.Data;
import jakarta.persistence.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a node in the Docker Swarm cluster
 */
@Entity
@Data
public class SwarmNode {
    @Id
    @GeneratedValue
    private Long id;

    /**
     * Docker swarm node ID
     */
    private String nodeId;

    /**
     * Node hostname
     */
    private String hostname;

    /**
     * Node role (manager or worker)
     */
    private String role;

    /**
     * Node status (ready, down, etc.)
     */
    private String status;

    /**
     * The server associated with this node
     */
    @OneToOne
    @JoinColumn(name = "server_id")
    private Server server;

    /**
     * Services running on this node
     */
    @OneToMany(mappedBy = "node", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<SwarmService> services = new ArrayList<>();
}