package com.tfg.infractory.web.event;

import java.util.UUID;
import org.springframework.context.ApplicationEvent;

/**
 * Event fired when Nebula is successfully deployed to a server.
 */
public class NebulaDeployedEvent extends ApplicationEvent {

    private final UUID serverId;
    private final Long nebulaConfigId;

    /**
     * Constructor for the NebulaDeployedEvent.
     * 
     * @param source         The event source
     * @param serverId       The ID of the server where Nebula was deployed
     * @param nebulaConfigId The ID of the Nebula configuration that was deployed
     */
    public NebulaDeployedEvent(Object source, UUID serverId, Long nebulaConfigId) {
        super(source);
        this.serverId = serverId;
        this.nebulaConfigId = nebulaConfigId;
    }

    /**
     * Gets the ID of the server where Nebula was deployed.
     * 
     * @return The server ID
     */
    public UUID getServerId() {
        return serverId;
    }

    /**
     * Gets the ID of the Nebula configuration that was deployed.
     * 
     * @return The Nebula configuration ID
     */
    public Long getNebulaConfigId() {
        return nebulaConfigId;
    }
}