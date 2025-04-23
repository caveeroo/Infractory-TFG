package com.tfg.infractory.web.event;

import org.springframework.context.ApplicationEvent;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;

public class LighthouseNebulaDeployedEvent extends ApplicationEvent {

    private final Nebula nebula;

    public LighthouseNebulaDeployedEvent(Object source, Nebula nebula) {
        super(source);
        this.nebula = nebula;
    }

    public Nebula getNebula() {
        return nebula;
    }
}