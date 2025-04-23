package com.tfg.infractory.domain.repository;

import com.tfg.infractory.domain.model.DockerConfig;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DockerConfigRepository extends JpaRepository<DockerConfig, Long> {
}