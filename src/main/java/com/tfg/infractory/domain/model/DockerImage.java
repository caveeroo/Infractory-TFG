package com.tfg.infractory.domain.model;

import jakarta.persistence.Id;
import lombok.Data;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;

@Entity
@Data
public class DockerImage {
    @Id
    @GeneratedValue
    private Long id;
    private String name;
    private String tag;
    private String repository;
}