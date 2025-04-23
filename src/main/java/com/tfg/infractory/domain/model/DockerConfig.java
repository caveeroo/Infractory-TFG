package com.tfg.infractory.domain.model;

import lombok.Data;
import jakarta.persistence.Id;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.OneToMany;
import jakarta.persistence.CascadeType;
import java.util.HashSet;
import java.util.Set;
import java.util.ArrayList;
import java.util.List;

@Entity
@Data
public class DockerConfig {
    @Id
    @GeneratedValue
    private Long id;
    private String name;
    private String content;

    /**
     * The target path inside the container where the config file should be mounted.
     * e.g., /etc/nginx/nginx.conf
     */
    private String targetPath;

    // Tags for filtering and targeting
    @ElementCollection
    private Set<String> tags = new HashSet<>();

    // Assignments of this config
    @OneToMany(mappedBy = "dockerConfig", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ConfigAssignment> assignments = new ArrayList<>();
}