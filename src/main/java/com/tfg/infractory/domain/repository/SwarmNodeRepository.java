package com.tfg.infractory.domain.repository;

import com.tfg.infractory.domain.model.SwarmNode;
import com.tfg.infractory.domain.model.Server;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

/**
 * Repository for SwarmNode entities
 */
public interface SwarmNodeRepository extends JpaRepository<SwarmNode, Long> {

    /**
     * Find a node by its Docker node ID
     */
    Optional<SwarmNode> findByNodeId(String nodeId);

    /**
     * Find a node by its associated server
     */
    Optional<SwarmNode> findByServer(Server server);

    /**
     * Find all nodes with a specific role
     */
    List<SwarmNode> findByRole(String role);

    /**
     * Find all nodes with a specific status
     */
    List<SwarmNode> findByStatus(String status);
}