package com.tfg.infractory.infrastructure.cloud.model.digitalocean;

import lombok.Data;

@Data
public class DOSSHKey {
    private Long id;
    private String fingerprint;
    private String public_key;
    private String name;

    // Getters and setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    public String getPublicKey() {
        return public_key;
    }

    public void setPublicKey(String public_key) {
        this.public_key = public_key;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return "DOSSHKey{" +
                "id=" + id +
                ", fingerprint='" + fingerprint + '\'' +
                ", public_key='" + public_key + '\'' +
                ", name='" + name + '\'' +
                '}';
    }
}