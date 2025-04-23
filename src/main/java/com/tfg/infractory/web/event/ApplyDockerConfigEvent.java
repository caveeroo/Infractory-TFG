package com.tfg.infractory.web.event;

import com.tfg.infractory.domain.model.Server;
import org.springframework.context.ApplicationEvent;

public class ApplyDockerConfigEvent extends ApplicationEvent {
    private final Server server;

    public ApplyDockerConfigEvent(Object source, Server server) {
        super(source);
        this.server = server;
    }

    public Server getServer() {
        return server;
    }
}