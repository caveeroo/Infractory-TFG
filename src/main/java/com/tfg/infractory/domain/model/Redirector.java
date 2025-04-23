package com.tfg.infractory.domain.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;
import jakarta.persistence.*;

import com.tfg.infractory.infrastructure.cloud.model.Details;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;

@Getter
@Setter
@Entity
@DiscriminatorValue("Redirector")
public class Redirector extends Server {

    public enum Protocol {
        DNS, TCP, HTTP, HTTPS, SMTP
    }

    @Enumerated(EnumType.STRING)
    private Protocol protocol;

    @ManyToOne
    @JoinColumn(name = "team_server_id")
    private TeamServer teamServer;

    @ManyToOne
    @JoinColumn(name = "phishing_id")
    private Phishing phishing;

    public Redirector() {
    }

    public Redirector(Instance instance, Nebula vpn, Details details, List<Domain> domains, String protocol,
            TeamServer teamServer, Phishing phishing, DockerConfig dockerConfig) {
        super(instance, vpn, details, domains, dockerConfig);
        this.protocol = Protocol.valueOf(protocol);
        this.teamServer = teamServer;
        this.phishing = phishing;
    }
}
