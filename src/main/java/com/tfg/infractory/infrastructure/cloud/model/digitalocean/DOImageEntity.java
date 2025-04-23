package com.tfg.infractory.infrastructure.cloud.model.digitalocean;

import java.util.List;
import java.time.Instant;
import jakarta.persistence.*;

@Entity
@Table(name = "do_images")
public class DOImageEntity {
    @Id
    private Long id;
    private String name;
    private String distribution;
    private String slug;
    private boolean isPublic;
    @ElementCollection
    private List<String> regions;
    private Instant createdAt;
    private String type;
    private int minDiskSize;
    private double sizeGigabytes;
    private String description;
    @ElementCollection
    private List<String> tags;
    private String status;
    private String errorMessage;

    public DOImageEntity() {
    }

    public DOImageEntity(Long id, String name, String distribution, String slug, boolean isPublic, List<String> regions,
            Instant createdAt, String type, int minDiskSize, double sizeGigabytes, String description,
            List<String> tags, String status, String errorMessage) {
        this.id = id;
        this.name = name;
        this.distribution = distribution;
        this.slug = slug;
        this.isPublic = isPublic;
        this.regions = regions;
        this.createdAt = createdAt;
        this.type = type;
        this.minDiskSize = minDiskSize;
        this.sizeGigabytes = sizeGigabytes;
        this.description = description;
        this.tags = tags;
        this.status = status;
        this.errorMessage = errorMessage;
    }

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

    public String getDistribution() {
        return distribution;
    }

    public void setDistribution(String distribution) {
        this.distribution = distribution;
    }

    public String getSlug() {
        return slug;
    }

    public void setSlug(String slug) {
        this.slug = slug;
    }

    public boolean isPublic() {
        return isPublic;
    }

    public void setPublic(boolean isPublic) {
        this.isPublic = isPublic;
    }

    public List<String> getRegions() {
        return regions;
    }

    public void setRegions(List<String> regions) {
        this.regions = regions;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public int getMinDiskSize() {
        return minDiskSize;
    }

    public void setMinDiskSize(int minDiskSize) {
        this.minDiskSize = minDiskSize;
    }

    public double getSizeGigabytes() {
        return sizeGigabytes;
    }

    public void setSizeGigabytes(double sizeGigabytes) {
        this.sizeGigabytes = sizeGigabytes;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<String> getTags() {
        return tags;
    }

    public void setTags(List<String> tags) {
        this.tags = tags;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}