package com.tfg.infractory.web.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.Set;
import java.util.Map;

@Data
public class NebulaConfigurationDTO {
    @NotNull
    private Boolean lighthouse;

    private String ip;
    private Integer subnet;
    private Long lighthouseId;
    private Set<String> lighthouseIps;
    private Set<String> roles;
    private Set<String> allowedCIDRs;
    private Set<String> allowedRoles;
    private Map<String, String> placementConstraints;
}