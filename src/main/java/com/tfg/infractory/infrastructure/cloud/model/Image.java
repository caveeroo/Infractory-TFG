package com.tfg.infractory.infrastructure.cloud.model;

import java.util.List;
import java.util.Date;
import java.time.Instant;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class Image {
    private Object id;
    private String name;
    private String distribution;
    private String slug;
    @JsonProperty("public")
    private boolean isPublic;
    private List<String> regions;
    @JsonProperty("created_at")
    private Instant createdAt;
    private String type;
    @JsonProperty("min_disk_size")
    private int minDiskSize;
    @JsonProperty("size_gigabytes")
    private double sizeGigabytes;
    private String description;
    private List<String> tags;
    private String status;
    @JsonProperty("error_message")
    private String errorMessage;

    // Default constructor
    public Image() {
    }

    // Constructor with all fields
    public Image(Object id, String name, String distribution, String slug, boolean isPublic, List<String> regions,
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

    // Add this constructor
    public Image(String id, String name, String distribution, String slug, boolean isPublic, List<String> regions,
            Date createdAt, String type, int minDiskSize, double sizeGigabytes, String description,
            List<String> tags, String status, String errorMessage) {
        this(id, name, distribution, slug, isPublic, regions, createdAt.toInstant(), type, minDiskSize, sizeGigabytes,
                description, tags, status, errorMessage);
    }

    public Object getId() {
        return id;
    }

    public void setId(Object id) {
        this.id = id;
    }

    // Legacy methods for backward compatibility
    public Long getLongId() {
        if (id instanceof Long) {
            return (Long) id;
        }
        return null;
    }

    public String getStringId() {
        if (id == null) {
            return null;
        }
        return id.toString();
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

    // Getter and setter for createdAt
    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    // toString method
    @Override
    public String toString() {
        return "Image{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", distribution='" + distribution + '\'' +
                ", slug='" + slug + '\'' +
                ", isPublic=" + isPublic +
                ", regions=" + regions +
                ", createdAt=" + createdAt +
                ", type='" + type + '\'' +
                ", minDiskSize=" + minDiskSize +
                ", sizeGigabytes=" + sizeGigabytes +
                ", description='" + description + '\'' +
                ", tags=" + tags +
                ", status='" + status + '\'' +
                ", errorMessage='" + errorMessage + '\'' +
                '}';
    }
}