package com.tfg.infractory.infrastructure.cloud.model.digitalocean;

import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Entity;

@Entity
@Table(name = "do_sizes")
public class DOSizeEntity {
    @Id
    private String slug;
    private String name;
    private int memory;
    private int vcpus;
    private int disk;
    private double priceMonthly;
    private double priceHourly;

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

    public int getMemory() {
        return memory;
    }

    public void setMemory(int memory) {
        this.memory = memory;
    }

    public int getVcpus() {
        return vcpus;
    }

    public void setVcpus(int vcpus) {
        this.vcpus = vcpus;
    }

    public int getDisk() {
        return disk;
    }

    public void setDisk(int disk) {
        this.disk = disk;
    }

    public double getPriceMonthly() {
        return priceMonthly;
    }

    public void setPriceMonthly(double priceMonthly) {
        this.priceMonthly = priceMonthly;
    }

    public double getPriceHourly() {
        return priceHourly;
    }

    public void setPriceHourly(double priceHourly) {
        this.priceHourly = priceHourly;
    }
}