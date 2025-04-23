package com.tfg.infractory.infrastructure.secrets.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
public class Secret {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String key; // Add this field
    private String type; // e.g., "CERTIFICATE", "SSH_KEY"

    @Column(columnDefinition = "TEXT")
    private String content;
}