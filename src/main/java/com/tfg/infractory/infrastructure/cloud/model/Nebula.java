package com.tfg.infractory.infrastructure.cloud.model;

import lombok.Data;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;

@Entity
@Data
public class Nebula {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "nebula_seq")
    private Long id;

    @NotNull
    private Boolean lighthouse;

    @NotBlank
    @Pattern(regexp = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", message = "Invalid IP address")
    private String ip;

    @NotNull
    @Min(0)
    @Max(32)
    private Integer subnet;

    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> lighthouseIps;

    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> roles;

    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> allowedCIDRs;

    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> allowedRoles;

    @ElementCollection(fetch = FetchType.EAGER)
    private Map<String, String> placementConstraints = new HashMap<>();

    // Custom getters

    public Boolean getLighthouse() {
        return this.lighthouse;
    }

    public String getIp() {
        return this.ip;
    }

    /**
     * Returns the IP address with its subnet in CIDR notation.
     * 
     * @return String representation of IP/subnet
     */
    public String getIpWithSubnet() {
        return this.ip + "/" + this.subnet;
    }

    public Map<String, String> getSwarmLabels() {
        Map<String, String> swarmLabels = new HashMap<>();
        if (this.allowedRoles.contains("listening_posts")) {
            swarmLabels.put("type", "listening_post");
        }
        if (this.allowedRoles.contains("c2_servers")) {
            swarmLabels.put("type", "c2_server");
        }
        // Add more mappings as needed
        return swarmLabels;
    }
}
