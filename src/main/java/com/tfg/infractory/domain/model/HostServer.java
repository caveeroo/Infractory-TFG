package com.tfg.infractory.domain.model;

import jakarta.persistence.*;
import java.util.UUID;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;

/**
 * Entity representing the host machine as a server in the system.
 * This is used when the host machine itself is part of the Nebula network
 * and acts as the Docker Swarm manager.
 */
@Entity
@Table(name = "host_server")
public class HostServer {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(name = "hostname")
    private String hostname;

    @OneToOne
    @JoinColumn(name = "vpn_id")
    private Nebula vpn;

    @Column(name = "is_swarm_manager")
    private boolean isSwarmManager;

    @Column(name = "nebula_deployed")
    private boolean nebulaDeployed;

    public HostServer() {
    }

    public HostServer(String hostname) {
        this.hostname = hostname;
        this.isSwarmManager = false;
        this.nebulaDeployed = false;
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public Nebula getVpn() {
        return vpn;
    }

    public void setVpn(Nebula vpn) {
        this.vpn = vpn;
    }

    public boolean isSwarmManager() {
        return isSwarmManager;
    }

    public void setSwarmManager(boolean swarmManager) {
        isSwarmManager = swarmManager;
    }

    public boolean isNebulaDeployed() {
        return nebulaDeployed;
    }

    public void setNebulaDeployed(boolean nebulaDeployed) {
        this.nebulaDeployed = nebulaDeployed;
    }
}