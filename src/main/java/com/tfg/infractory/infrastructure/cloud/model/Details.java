package com.tfg.infractory.infrastructure.cloud.model;

import lombok.Getter;
import lombok.Setter;
import jakarta.persistence.Id;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;

@Getter
@Setter
@Entity
public class Details {
    @Id
    @GeneratedValue
    private Long id;
    private String name;
    private String description;

    public Details(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public Details() {
    }
}
