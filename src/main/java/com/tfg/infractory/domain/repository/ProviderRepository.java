package com.tfg.infractory.domain.repository;

import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.JpaRepository;

import com.tfg.infractory.domain.model.Provider;

@Repository
public interface ProviderRepository extends JpaRepository<Provider, String> {
}
