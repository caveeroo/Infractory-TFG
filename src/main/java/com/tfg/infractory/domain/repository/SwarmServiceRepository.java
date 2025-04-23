package com.tfg.infractory.domain.repository;

import com.tfg.infractory.domain.model.SwarmService;
import com.tfg.infractory.domain.model.SwarmNode;
import com.tfg.infractory.domain.model.DockerImage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Repository for SwarmService entities
 */
public interface SwarmServiceRepository extends JpaRepository<SwarmService, Long> {

    /**
     * Find a service by its Docker service ID
     */
    Optional<SwarmService> findByServiceId(String serviceId);

    /**
     * Find all services running on a specific node
     */
    List<SwarmService> findByNode(SwarmNode node);

    /**
     * Find all services using a specific Docker image
     */
    List<SwarmService> findByDockerImage(DockerImage dockerImage);

    /**
     * Find all services with a specific status
     */
    List<SwarmService> findByStatus(String status);

    /**
     * Find all services that have a specific tag
     */
    @Query("SELECT s FROM SwarmService s JOIN s.tags t WHERE t = :tag")
    List<SwarmService> findByTag(@Param("tag") String tag);

    /**
     * Find all services that have all of the specified tags
     */
    @Query("SELECT s FROM SwarmService s JOIN s.tags t WHERE t IN :tags GROUP BY s HAVING COUNT(DISTINCT t) = :tagCount")
    List<SwarmService> findByAllTags(@Param("tags") Set<String> tags, @Param("tagCount") Long tagCount);

    /**
     * Find all services running on any of the specified nodes.
     */
    List<SwarmService> findByNodeIn(List<SwarmNode> nodes);

    /**
     * Find all services that contain the specified tag in their tag set.
     * Note: This uses the default Spring Data JPA query generation based on method
     * name.
     */
    List<SwarmService> findByTagsContaining(String tag);
}