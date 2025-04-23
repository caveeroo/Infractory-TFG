package com.tfg.infractory.web.event;

import org.springframework.context.ApplicationEvent;
import com.tfg.infractory.domain.model.HostServer;

/**
 * Event fired when Nebula is successfully deployed to the host machine.
 * This event serves as a trigger for Docker Swarm initialization.
 */
public class HostNebulaDeployedEvent extends ApplicationEvent {

    private final HostServer hostServer;
    private final boolean interfaceVerified;

    /**
     * Constructor for the HostNebulaDeployedEvent.
     * 
     * @param source            The event source
     * @param hostServer        The host server where Nebula was deployed
     * @param interfaceVerified Whether the Nebula interface was verified to be up
     *                          and running
     */
    public HostNebulaDeployedEvent(Object source, HostServer hostServer, boolean interfaceVerified) {
        super(source);
        this.hostServer = hostServer;
        this.interfaceVerified = interfaceVerified;
    }

    /**
     * Gets the host server where Nebula was deployed.
     * 
     * @return The host server
     */
    public HostServer getHostServer() {
        return hostServer;
    }

    /**
     * Checks if the Nebula interface was verified to be up and running.
     * 
     * @return true if verified, false otherwise
     */
    public boolean isInterfaceVerified() {
        return interfaceVerified;
    }
}