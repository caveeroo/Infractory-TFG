package com.tfg.infractory.infrastructure.nebula.model;

import lombok.Data;
import jakarta.persistence.Id;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;

@Entity
@Data
public class NebulaCertificate {
    @Id
    @GeneratedValue
    private Long id;
    private String name;
    private String ip;
    private String groups;
    private String certContent;
    private String keyContent;
}