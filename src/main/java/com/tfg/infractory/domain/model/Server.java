package com.tfg.infractory.domain.model;

import lombok.Getter;
import lombok.Setter;
import java.util.List;
import java.util.ArrayList;
import java.io.Serializable;
import jakarta.persistence.*;

import com.tfg.infractory.infrastructure.cloud.model.Details;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;

@Setter
@Getter
@Entity
@Inheritance(strategy = InheritanceType.JOINED)
public abstract class Server implements Serializable {
    @OneToOne(cascade = CascadeType.ALL)
    private Instance instance;

    @OneToOne(cascade = CascadeType.ALL)
    private Nebula vpn;

    @OneToOne(cascade = CascadeType.ALL)
    private Details details;

    @OneToMany(mappedBy = "server", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Domain> domains = new ArrayList<>();

    private Boolean online;

    @ManyToOne(cascade = CascadeType.ALL)
    private DockerConfig dockerConfig;

    @ManyToOne(cascade = CascadeType.ALL)
    private Domain activedomain;

    @Id
    @GeneratedValue
    private Long id;

    @Column(nullable = true)
    private String containerId;

    @Column(nullable = true)
    private Boolean isSwarmManager = false;

    @Column(nullable = true)
    private String swarmToken;

    public Server(Instance instance, Nebula vpn, Details details, List<Domain> domains, DockerConfig dockerConfig) {
        this.instance = instance;
        this.vpn = vpn;
        this.details = details;
        this.setDomains(domains);
        this.dockerConfig = dockerConfig;
        this.online = true;
    }

    public Server() {
    }

    public Boolean shutDown() {
        this.online = false;
        return this.online;
    }

    public Boolean isOnline() {
        return this.online;
    }

    public void setDomains(List<Domain> domains) {
        this.domains.clear();
        if (domains != null) {
            for (Domain domain : domains) {
                addDomain(domain);
            }
        }
    }

    public void addDomain(Domain domain) {
        domain.setServer(this);
        this.domains.add(domain);
        if (this.domains.size() == 1) {
            this.activedomain = domain;
        }
    }

    public void setInstance(Instance instance) {
        this.instance = instance;
    }

    public Instance getInstance() {
        return this.instance;
    }

    public void setDockerConfig(DockerConfig dockerConfig) {
        this.dockerConfig = dockerConfig;
    }

    public DockerConfig getDockerConfig() {
        return this.dockerConfig;
    }

    public Boolean getIsSwarmManager() {
        return isSwarmManager;
    }

    public void setIsSwarmManager(Boolean isSwarmManager) {
        this.isSwarmManager = isSwarmManager;
    }

    public String getSwarmToken() {
        return swarmToken;
    }

    public void setSwarmToken(String swarmToken) {
        this.swarmToken = swarmToken;
    }

    public String getContainerId() {
        return containerId;
    }

    public void setContainerId(String containerId) {
        this.containerId = containerId;
    }

    public Nebula getVpn() {
        return this.vpn;
    }

    public void setVpn(Nebula vpn) {
        this.vpn = vpn;
    }
}
