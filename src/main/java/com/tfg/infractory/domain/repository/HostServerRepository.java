package com.tfg.infractory.domain.repository;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tfg.infractory.domain.model.HostServer;

/**
 * Repository for managing HostServer entities.
 */
@Repository
public interface HostServerRepository extends JpaRepository<HostServer, UUID> {

    /**
     * Finds the first host server ordered by ID.
     * This is useful when there should only be one host server in the system.
     * 
     * @return An Optional containing the host server if found, empty otherwise
     */
    Optional<HostServer> findFirstByOrderByIdAsc();
}