package com.tfg.infractory.domain.repository;

import com.tfg.infractory.domain.model.ConfigAssignment;
import com.tfg.infractory.domain.model.ConfigAssignment.TargetType;
import com.tfg.infractory.domain.model.Instance;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ConfigAssignmentRepository extends JpaRepository<ConfigAssignment, Long> {

    /**
     * Find assignments targeting a specific server type
     */
    List<ConfigAssignment> findByTargetTypeAndServerType(TargetType targetType, String serverType);

    /**
     * Find assignments targeting a specific instance
     */
    List<ConfigAssignment> findByTargetTypeAndInstance(TargetType targetType, Instance instance);

    /**
     * Find all assignments for a given Docker config
     */
    List<ConfigAssignment> findByDockerConfigId(Long dockerConfigId);
}