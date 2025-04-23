package com.tfg.infractory.infrastructure.cloud.repository;

import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.JpaRepository;

import com.tfg.infractory.infrastructure.cloud.model.digitalocean.DORegionEntity;

@Repository
public interface DORegionRepository extends JpaRepository<DORegionEntity, String> {
}