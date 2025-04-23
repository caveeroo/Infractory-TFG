package com.tfg.infractory.domain.repository;

import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.JpaRepository;

import com.tfg.infractory.infrastructure.cloud.model.Details;

@Repository
public interface DetailsRepository extends JpaRepository<Details, Long> {
}
