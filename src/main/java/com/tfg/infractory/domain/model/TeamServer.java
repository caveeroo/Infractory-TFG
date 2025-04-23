package com.tfg.infractory.domain.model;

import lombok.Getter;
import lombok.Setter;
import java.util.List;
import java.util.ArrayList;
import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;
import jakarta.persistence.CascadeType;

import com.tfg.infractory.infrastructure.cloud.model.Details;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;

@Getter
@Setter
@Entity
public class TeamServer extends Server {
    @OneToMany(mappedBy = "teamServer", cascade = CascadeType.ALL)
    private List<Redirector> redirectorList = new ArrayList<>();

    public TeamServer(Instance instance, Nebula vpn, Details details, List<Domain> domains,
            List<Redirector> redirectors, DockerConfig dockerConfig) {
        super(instance, vpn, details, domains, dockerConfig);
        this.redirectorList = redirectors;
    }

    public TeamServer() {
    }

    public Boolean addRedirector(Redirector redirector) {
        if (this.redirectorList == null) {
            this.redirectorList = new ArrayList<>();
        }
        redirector.setTeamServer(this);
        return this.redirectorList.add(redirector);
    }

    public List<Redirector> getRedirectors() {
        return this.redirectorList;
    }
}
