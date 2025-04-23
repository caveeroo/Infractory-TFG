package com.tfg.infractory.domain.model;

import lombok.Getter;
import lombok.Setter;
import jakarta.persistence.*;

@Getter
@Setter
@Entity
public class Provider {
    @Id
    private String name;

    public Provider() {

    }

    public Provider(String name) {
        this.name = name;
    }
}
