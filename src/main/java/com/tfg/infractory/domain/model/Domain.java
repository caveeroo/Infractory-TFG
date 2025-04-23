package com.tfg.infractory.domain.model;

import lombok.Getter;
import lombok.Setter;
import jakarta.persistence.*;

@Getter
@Setter
@Entity
public class Domain {
    private String domain;
    private String tld;

    @ManyToOne
    private Provider provider;

    @ManyToOne
    @JoinColumn(name = "server_id")
    private Server server;

    @Id
    @GeneratedValue
    private Long id;

    public Domain(String domain, Provider provider) {
        this.domain = domain;
        this.tld = extractTLD(domain);
        this.provider = provider;
    }

    private String extractTLD(String domain) {
        if (domain == null || !domain.contains(".")) {
            return null;
        }
        return domain.substring(domain.lastIndexOf('.') + 1);
    }

    public Domain() {
    }
}
