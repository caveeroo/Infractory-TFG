package com.tfg.infractory.domain.repository;

import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.JpaRepository;

import com.tfg.infractory.domain.model.Server;
import com.tfg.infractory.domain.model.Instance;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;

@Repository
public interface ServerRepository extends JpaRepository<Server, Long> {
    Server findByVpn(Nebula vpn);

    Server findByIsSwarmManagerTrue();

    Server findByInstance(Instance instance);
}
