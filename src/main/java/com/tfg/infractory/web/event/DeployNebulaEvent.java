package com.tfg.infractory.web.event;

import org.springframework.context.ApplicationEvent;

public class DeployNebulaEvent extends ApplicationEvent {
    private final Long serverId;
    private final Long nebulaConfigId;

    public DeployNebulaEvent(Object source, Long serverId, Long nebulaConfigId) {
        super(source);
        this.serverId = serverId;
        this.nebulaConfigId = nebulaConfigId;
    }

    public Long getServerId() {
        return serverId;
    }

    public Long getNebulaConfigId() {
        return nebulaConfigId;
    }
}