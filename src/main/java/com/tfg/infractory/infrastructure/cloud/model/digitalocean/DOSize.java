package com.tfg.infractory.infrastructure.cloud.model.digitalocean;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.tfg.infractory.infrastructure.cloud.model.Size;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class DOSize implements Size {
    private String slug;
    private int memory;
    private int vcpus;
    private int disk;
    private double transfer;
    @JsonProperty("price_monthly")
    private double priceMonthly;
    @JsonProperty("price_hourly")
    private double priceHourly;
    private boolean available;
    private String description;
    private List<String> regions;

    public DOSize() {
    }

    public String getSlug() {
        return slug;
    }

    public void setSlug(String slug) {
        this.slug = slug;
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

    public double getTransfer() {
        return transfer;
    }

    public void setTransfer(double transfer) {
        this.transfer = transfer;
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

    public List<String> getRegions() {
        return regions;
    }

    public void setRegions(List<String> regions) {
        this.regions = regions;
    }

    public boolean isAvailable() {
        return available;
    }

    public void setAvailable(boolean available) {
        this.available = available;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String getId() {
        return getSlug();
    }

    @Override
    public String getName() {
        return slug;
    }

    @Override
    public int getCpuCount() {
        return getVcpus();
    }

    @Override
    public int getMemoryMB() {
        return getMemory();
    }

    public DOSize(String slug, String description, int memory, int vcpus, int disk, double priceMonthly,
            double priceHourly) {
        this.slug = slug;
        this.description = description;
        this.memory = memory;
        this.vcpus = vcpus;
        this.disk = disk;
        this.priceMonthly = priceMonthly;
        this.priceHourly = priceHourly;
    }
}