package com.tfg.infractory.infrastructure.cloud.model.digitalocean;

import java.util.List;
import java.util.Optional;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class Droplet {
    private Long id;
    private String name;
    private Integer memory;
    private Integer vcpus;
    private Integer disk;
    private Boolean locked;
    private String status;
    private String kernel;

    @JsonProperty("created_at")
    private String createdAt;

    private List<String> features;

    @JsonProperty("backup_ids")
    private List<Long> backupIds;

    @JsonProperty("next_backup_window")
    private Object nextBackupWindow;

    @JsonProperty("snapshot_ids")
    private List<Long> snapshotIds;

    private Object image;

    @JsonProperty("volume_ids")
    private List<String> volumeIds;

    private Object size;

    @JsonProperty("size_slug")
    private String sizeSlug;

    private Networks networks;
    private Object region;
    private List<String> tags;

    // Getters and setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getMemory() {
        return memory;
    }

    public void setMemory(Integer memory) {
        this.memory = memory;
    }

    public Integer getVcpus() {
        return vcpus;
    }

    public void setVcpus(Integer vcpus) {
        this.vcpus = vcpus;
    }

    public Integer getDisk() {
        return disk;
    }

    public void setDisk(Integer disk) {
        this.disk = disk;
    }

    public Boolean getLocked() {
        return locked;
    }

    public void setLocked(Boolean locked) {
        this.locked = locked;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getKernel() {
        return kernel;
    }

    public void setKernel(String kernel) {
        this.kernel = kernel;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public List<String> getFeatures() {
        return features;
    }

    public void setFeatures(List<String> features) {
        this.features = features;
    }

    public List<Long> getBackupIds() {
        return backupIds;
    }

    public void setBackupIds(List<Long> backupIds) {
        this.backupIds = backupIds;
    }

    public Object getNextBackupWindow() {
        return nextBackupWindow;
    }

    public void setNextBackupWindow(Object nextBackupWindow) {
        this.nextBackupWindow = nextBackupWindow;
    }

    public List<Long> getSnapshotIds() {
        return snapshotIds;
    }

    public void setSnapshotIds(List<Long> snapshotIds) {
        this.snapshotIds = snapshotIds;
    }

    public Object getImage() {
        return image;
    }

    public void setImage(Object image) {
        this.image = image;
    }

    public List<String> getVolumeIds() {
        return volumeIds;
    }

    public void setVolumeIds(List<String> volumeIds) {
        this.volumeIds = volumeIds;
    }

    public Object getSize() {
        return size;
    }

    public void setSize(Object size) {
        this.size = size;
    }

    public String getSizeSlug() {
        return sizeSlug;
    }

    public void setSizeSlug(String sizeSlug) {
        this.sizeSlug = sizeSlug;
    }

    public Networks getNetworks() {
        return networks;
    }

    public void setNetworks(Networks networks) {
        this.networks = networks;
    }

    public Object getRegion() {
        return region;
    }

    public void setRegion(Object region) {
        this.region = region;
    }

    public List<String> getTags() {
        return tags;
    }

    public void setTags(List<String> tags) {
        this.tags = tags;
    }

    public Optional<String> getPublicIpv4Address() {
        if (networks != null && networks.getV4() != null) {
            return networks.getV4().stream()
                    .filter(network -> "public".equals(network.getType()))
                    .map(Network::getIpAddress)
                    .findFirst();
        }
        return Optional.empty();
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Networks {
        private List<Network> v4;
        private List<Network> v6;

        public List<Network> getV4() {
            return v4;
        }

        public void setV4(List<Network> v4) {
            this.v4 = v4;
        }

        public List<Network> getV6() {
            return v6;
        }

        public void setV6(List<Network> v6) {
            this.v6 = v6;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Network {
        @JsonProperty("ip_address")
        private String ipAddress;
        private String netmask;
        private String gateway;
        private String type;

        public String getIpAddress() {
            return ipAddress;
        }

        public void setIpAddress(String ipAddress) {
            this.ipAddress = ipAddress;
        }

        public String getNetmask() {
            return netmask;
        }

        public void setNetmask(String netmask) {
            this.netmask = netmask;
        }

        public String getGateway() {
            return gateway;
        }

        public void setGateway(String gateway) {
            this.gateway = gateway;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }
    }

    @JsonProperty("ssh_keys")
    private List<String> ssh_keys;

    @JsonProperty("ssh_keys")
    public List<String> getSshKeys() {
        return ssh_keys;
    }

    @JsonProperty("ssh_keys")
    public void setSshKeys(List<String> sshKeys) {
        this.ssh_keys = sshKeys;
    }

    @Override
    public String toString() {
        return "Droplet{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", region='" + region + '\'' +
                ", size='" + size + '\'' +
                ", image='" + image + '\'' +
                ", ssh_keys=" + ssh_keys +
                // Add other relevant fields
                '}';
    }
}