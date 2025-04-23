package com.tfg.infractory.domain.model;

import lombok.Getter;
import lombok.Setter;
import java.util.Date;
import java.net.InetAddress;

import jakarta.persistence.Id;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;

import com.tfg.infractory.infrastructure.ssh.model.SSHKey;

@Setter
@Getter
@Entity
public class Instance {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    private Provider provider;

    private String name;
    private String imageId;
    private String size;
    private String region;
    private String providerId;
    private String type;

    @Column(columnDefinition = "TIMESTAMP")
    private Date created;

    @Column(columnDefinition = "TIMESTAMP")
    private Date destroyed;

    @Column(columnDefinition = "BOOLEAN DEFAULT false")
    private Boolean isSwarmManager = false;

    @Enumerated(EnumType.STRING)
    private InstanceStatus status;

    @Column(columnDefinition = "INET")
    private InetAddress ip;

    // Default username for SSH access (ubuntu, ec2-user, etc.)
    private String defaultUser;

    public Instance(Provider provider, String region, InetAddress ip) {
        this.provider = provider;
        this.region = region;
        this.ip = ip;
        this.created = new Date();
        this.type = provider != null && "Local".equals(provider.getName()) ? "local" : "remote";
        this.status = InstanceStatus.CREATING;
    }

    public Instance() {
        this.created = new Date();
        this.type = "remote"; // Default to remote for empty constructor
        this.status = InstanceStatus.CREATING;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public void setImageId(String imageId) {
        this.imageId = imageId;
    }

    public void setSize(String size) {
        this.size = size;
    }

    public void setProviderId(String providerId) {
        this.providerId = providerId;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    @ManyToOne
    private SSHKey sshKey;

    public void setSshKey(SSHKey sshKey) {
        this.sshKey = sshKey;
    }

    public SSHKey getSshKey() {
        return sshKey;
    }

    @Column(nullable = true)
    private Integer port;

    public void setPort(Integer port) {
        this.port = port;
    }

    public Integer getPort() {
        return port;
    }

    public void setStatus(InstanceStatus status) {
        this.status = status;
    }

    public InstanceStatus getStatus() {
        return status;
    }

    public Provider getProvider() {
        return provider;
    }

    public void setProvider(Provider provider) {
        this.provider = provider;
        if (provider != null) {
            this.type = "Local".equals(provider.getName()) ? "local" : "remote";
        }
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getImageId() {
        return imageId;
    }

    public String getSize() {
        return size;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getProviderId() {
        return providerId;
    }

    public Date getCreated() {
        return created;
    }

    public void setCreated(Date created) {
        this.created = created;
    }

    public Date getDestroyed() {
        return destroyed;
    }

    public void setDestroyed(Date destroyed) {
        this.destroyed = destroyed;
    }

    public InetAddress getIp() {
        return ip;
    }

    public void setIp(InetAddress ip) {
        this.ip = ip;
    }

    public Boolean getIsSwarmManager() {
        return isSwarmManager;
    }

    public void setIsSwarmManager(Boolean isSwarmManager) {
        this.isSwarmManager = isSwarmManager;
    }

    public enum InstanceStatus {
        CREATING,
        RUNNING,
        STOPPED,
        DELETED,
        ERROR
    }
}
