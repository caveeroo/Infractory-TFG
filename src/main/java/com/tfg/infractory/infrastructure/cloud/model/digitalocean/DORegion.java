package com.tfg.infractory.infrastructure.cloud.model.digitalocean;

import java.util.List;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.tfg.infractory.infrastructure.cloud.model.Region;

@JsonIgnoreProperties(ignoreUnknown = true)
public class DORegion implements Region {
    private String name;
    private String slug;
    private List<String> features;
    private boolean available;
    private List<String> sizes;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSlug() {
        return slug;
    }

    public void setSlug(String slug) {
        this.slug = slug;
    }

    public List<String> getFeatures() {
        return features;
    }

    public void setFeatures(List<String> features) {
        this.features = features;
    }

    public void setAvailable(boolean available) {
        this.available = available;
    }

    public List<String> getSizes() {
        return sizes;
    }

    public void setSizes(List<String> sizes) {
        this.sizes = sizes;
    }

    @Override
    public String getId() {
        return getSlug();
    }

    @Override
    public boolean isAvailable() {
        return available;
    }

    public DORegion(String slug, String name) {
        this.slug = slug;
        this.name = name;
    }

    // Add this default constructor
    public DORegion() {
    }
}