package com.tfg.infractory.infrastructure.ssh.repository;

import com.tfg.infractory.infrastructure.ssh.model.SSHKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SSHKeyRepository extends JpaRepository<SSHKey, Long> {
    SSHKey findByName(String name);
}