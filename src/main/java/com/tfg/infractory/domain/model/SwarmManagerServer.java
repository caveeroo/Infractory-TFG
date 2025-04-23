package com.tfg.infractory.domain.model;

import lombok.Getter;
import lombok.Setter;
import jakarta.persistence.Entity;
import jakarta.persistence.DiscriminatorValue;
import java.util.List;
import com.tfg.infractory.infrastructure.cloud.model.Details;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;

@Getter
@Setter
@Entity
@DiscriminatorValue("SwarmManager") // Ensures correct discriminator value if using SINGLE_TABLE inheritance
public class SwarmManagerServer extends Server {

    public SwarmManagerServer() {
        super();
    }

    public SwarmManagerServer(Instance instance, Nebula vpn, Details details, List<Domain> domains,
            DockerConfig dockerConfig) {
        super(instance, vpn, details, domains, dockerConfig);
    }
}