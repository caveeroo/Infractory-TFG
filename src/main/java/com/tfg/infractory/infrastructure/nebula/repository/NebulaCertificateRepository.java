package com.tfg.infractory.infrastructure.nebula.repository;

import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.JpaRepository;
import com.tfg.infractory.infrastructure.nebula.model.NebulaCertificate;

@Repository
public interface NebulaCertificateRepository extends JpaRepository<NebulaCertificate, Long> {
    NebulaCertificate findByName(String name);
}