package com.tfg.infractory.web.event;

import org.springframework.context.ApplicationEvent;
import com.tfg.infractory.domain.model.Server;

public class ServerCreatedEvent extends ApplicationEvent {
    private final Server server;

    public ServerCreatedEvent(Object source, Server server) {
        super(source);
        this.server = server;
    }

    public Server getServer() {
        return server;
    }
}