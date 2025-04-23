package com.tfg.infractory.domain.repository;

import com.tfg.infractory.domain.model.DockerImage;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DockerImageRepository extends JpaRepository<DockerImage, Long> {
}