package com.tfg.infractory.domain.repository;

import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.JpaRepository;

import com.tfg.infractory.domain.model.Instance;

@Repository
public interface InstanceRepository extends JpaRepository<Instance, Long> {
    List<Instance> findByIpIsNull();

    List<Instance> findByStatusNot(Instance.InstanceStatus status);

    Optional<Instance> findByName(String name);

    // Added method to check existence by name
    boolean existsByName(String name);

    // Added method to check existence by type
    boolean existsByType(String type);
}
