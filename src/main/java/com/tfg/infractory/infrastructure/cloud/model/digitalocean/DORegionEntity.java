package com.tfg.infractory.infrastructure.cloud.model.digitalocean;

import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Entity;

@Entity
@Table(name = "do_regions")
public class DORegionEntity {
    @Id
    private String slug;
    private String name;
    private boolean available;
    // Add other necessary fields

    public String getSlug() {
        return slug;
    }

    public void setSlug(String slug) {
        this.slug = slug;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isAvailable() {
        return available;
    }

    public void setAvailable(boolean available) {
        this.available = available;
    }
}