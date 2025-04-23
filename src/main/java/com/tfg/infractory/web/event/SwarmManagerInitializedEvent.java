package com.tfg.infractory.web.event;

import org.springframework.context.ApplicationEvent;
import com.tfg.infractory.domain.model.Instance;
import com.tfg.infractory.domain.model.Server;
import com.tfg.infractory.domain.model.HostServer;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;

/**
 * Event fired when a swarm manager is initialized.
 * This can be either a HostServer (preferred) or a traditional Instance-based
 * server.
 */
public class SwarmManagerInitializedEvent extends ApplicationEvent {

    private final Server swarmManagerServer;
    private final HostServer hostServer;
    private Instance swarmManagerInstance;
    private Nebula swarmManagerNebula;

    /**
     * Constructor for HostServer-based swarm manager.
     * 
     * @param source     The event source
     * @param hostServer The host server that acts as swarm manager
     */
    public SwarmManagerInitializedEvent(Object source, HostServer hostServer) {
        super(source);
        this.swarmManagerServer = null;
        this.hostServer = hostServer;
        this.swarmManagerInstance = null;
        this.swarmManagerNebula = hostServer.getVpn();
    }

    /**
     * Legacy constructor for Instance-based swarm manager.
     * 
     * @param source               The event source
     * @param swarmManagerInstance The instance that acts as swarm manager
     * @param swarmManagerNebula   The Nebula configuration for the swarm manager
     */
    public SwarmManagerInitializedEvent(Object source, Instance swarmManagerInstance, Nebula swarmManagerNebula) {
        super(source);
        this.swarmManagerServer = null;
        this.hostServer = null;
        this.swarmManagerInstance = swarmManagerInstance;
        this.swarmManagerNebula = swarmManagerNebula;
    }

    /**
     * Legacy constructor for Server-based swarm manager.
     * 
     * @param source             The event source
     * @param swarmManagerServer The server that acts as swarm manager
     */
    public SwarmManagerInitializedEvent(Object source, Server swarmManagerServer) {
        super(source);
        this.swarmManagerServer = swarmManagerServer;
        this.hostServer = null;
        this.swarmManagerInstance = swarmManagerServer.getInstance();
        this.swarmManagerNebula = swarmManagerServer.getVpn();
    }

    /**
     * Gets the server that acts as swarm manager.
     * 
     * @return The swarm manager server
     */
    public Server getSwarmManagerServer() {
        return swarmManagerServer;
    }

    /**
     * Gets the host server that acts as swarm manager.
     * 
     * @return The host server or null if using a traditional server
     */
    public HostServer getHostServer() {
        return hostServer;
    }

    /**
     * Gets the instance that acts as swarm manager (legacy).
     * 
     * @return The swarm manager instance
     */
    public Instance getSwarmManagerInstance() {
        if (hostServer != null) {
            return null;
        }
        return swarmManagerInstance;
    }

    /**
     * Gets the Nebula configuration for the swarm manager.
     * 
     * @return The swarm manager Nebula configuration
     */
    public Nebula getSwarmManagerNebula() {
        return swarmManagerNebula;
    }

    /**
     * Checks if the swarm manager is the host machine.
     * 
     * @return true if the swarm manager is the host machine, false otherwise
     */
    public boolean isHostSwarmManager() {
        return hostServer != null;
    }
}