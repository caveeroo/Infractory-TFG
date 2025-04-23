package com.tfg.infractory.infrastructure.secrets.repository;

import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.JpaRepository;
import com.tfg.infractory.infrastructure.secrets.model.Secret;

import java.util.List;

@Repository
public interface SecretsRepository extends JpaRepository<Secret, Long> {
    List<Secret> findByName(String name);
}