package com.tfg.infractory.infrastructure.docker.listener;

import java.util.Optional;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import com.tfg.infractory.domain.model.HostServer;
import com.tfg.infractory.domain.service.HostServerService;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;
import com.tfg.infractory.infrastructure.docker.service.DockerSwarmService;
import com.tfg.infractory.infrastructure.nebula.service.NebulaDeploymentService;
import com.tfg.infractory.infrastructure.nebula.service.NebulaService;
import com.tfg.infractory.web.dto.NebulaConfigurationDTO;
import com.tfg.infractory.web.event.NebulaDeployedEvent;
import com.tfg.infractory.web.event.HostNebulaDeployedEvent;
import com.tfg.infractory.web.event.LighthouseNebulaDeployedEvent;
import com.tfg.infractory.domain.model.Server;
import com.tfg.infractory.domain.repository.ServerRepository;

/**
 * Listener that initializes the host machine as the Docker Swarm manager.
 * This listener is triggered when the application context is refreshed.
 */
@Component
public class SwarmManagerDeploymentListener {

    private static final Logger logger = LoggerFactory.getLogger(SwarmManagerDeploymentListener.class);

    private final HostServerService hostServerService;
    private final DockerSwarmService dockerSwarmService;
    private final NebulaService nebulaService;
    private final NebulaDeploymentService nebulaDeploymentService;
    private final ServerRepository serverRepository;

    private final CountDownLatch initializationLatch = new CountDownLatch(1);
    private final AtomicBoolean initialized = new AtomicBoolean(false);

    @Autowired
    public SwarmManagerDeploymentListener(
            HostServerService hostServerService,
            DockerSwarmService dockerSwarmService,
            NebulaService nebulaService,
            NebulaDeploymentService nebulaDeploymentService,
            ApplicationEventPublisher eventPublisher,
            ServerRepository serverRepository) {
        this.hostServerService = hostServerService;
        this.dockerSwarmService = dockerSwarmService;
        this.nebulaService = nebulaService;
        this.nebulaDeploymentService = nebulaDeploymentService;
        this.serverRepository = serverRepository;
    }

    /**
     * Initializes the host machine as the Docker Swarm manager when the application
     * starts.
     * This method creates a HostServer entity if it doesn't exist, configures
     * Nebula,
     * deploys Nebula to the host, and then initializes Docker Swarm on the host.
     * 
     * @param event The ContextRefreshedEvent
     */
    @EventListener
    public void handleApplicationStartup(ContextRefreshedEvent event) {
        logger.info("Initializing host machine as Docker Swarm manager");

        // Run initialization in a separate thread to avoid blocking app startup
        CompletableFuture.runAsync(() -> {
            try {
                logger.info("Beginning host initialization sequence...");

                // Step 1: Get or create the host server
                final HostServer hostServer = getOrCreateHostServer();

                // Step 2: Configure Nebula if needed
                final HostServer configuredHostServer;
                if (hostServer.getVpn() == null) {
                    logger.info("Host server has no Nebula configuration. Creating one...");
                    Nebula nebulaConfig = createNebulaConfigForHost();
                    configuredHostServer = hostServerService.setNebulaConfig(hostServer, nebulaConfig);
                    logger.info("Created Nebula configuration for host server with IP: {}", nebulaConfig.getIp());
                } else {
                    logger.info("Host server already has Nebula configuration with IP: {}",
                            hostServer.getVpn().getIp());
                    configuredHostServer = hostServer;
                }

                // Step 3: Check if the host is already deployed and ready
                if (configuredHostServer.isNebulaDeployed()
                        && isNebulaInterfaceUpAndRunning(configuredHostServer.getVpn().getIp())) {
                    logger.info(
                            "Host Nebula is already deployed and running. Proceeding with Docker Swarm initialization...");
                    initializeDockerSwarmWithRetry(configuredHostServer);
                    return;
                }

                // Step 4: Check if a lighthouse exists and is deployed
                boolean lighthouseExists = checkForDeployedLighthouse();

                if (!lighthouseExists) {
                    logger.info("No deployed lighthouse found. Waiting for a lighthouse to be deployed...");

                    // We'll wait for a lighthouse to be deployed via the
                    // LighthouseNebulaDeployedEvent
                    initializationLatch.countDown(); // Release the latch to avoid blocking
                    return;
                }

                // Step 5: Deploy Nebula to host if a lighthouse exists
                logger.info("Lighthouse found. Proceeding with Nebula deployment on host...");

                deployNebulaToHostWithVerification(configuredHostServer)
                        .thenApply(result -> {
                            if (!result) {
                                logger.error("Failed to deploy Nebula to host or verify its operation");
                                initializationLatch.countDown();
                                return false;
                            }

                            // Step 6: Initialize Docker Swarm only after Nebula is confirmed working
                            logger.info("Nebula deployed and verified. Now initializing Docker Swarm...");
                            initializeDockerSwarmWithRetry(configuredHostServer);
                            return true;
                        })
                        .whenComplete((result, ex) -> {
                            if (ex != null) {
                                logger.error("Failed in the host initialization sequence", ex);
                            } else if (Boolean.TRUE.equals(result)) {
                                logger.info("Host initialization sequence completed successfully");
                                initialized.set(true);
                            } else {
                                logger.error("Host initialization sequence failed");
                            }
                            initializationLatch.countDown();
                        });
            } catch (Exception e) {
                logger.error("Exception during host initialization sequence", e);
                initializationLatch.countDown();
            }
        });
    }

    /**
     * Handles the NebulaDeployedEvent for the host server.
     * This method is triggered when Nebula is successfully deployed to the host.
     * 
     * @param event The NebulaDeployedEvent
     */
    @EventListener
    public void handleNebulaDeployed(NebulaDeployedEvent event) {
        Optional<HostServer> hostServerOpt = hostServerService.findById(event.getServerId());
        if (hostServerOpt.isPresent()) {
            HostServer hostServer = hostServerOpt.get();
            logger.info("Nebula deployed to host server: {}", hostServer.getId());

            // Mark the host server as having Nebula deployed
            hostServerService.markNebulaDeployed(hostServer);
        }
    }

    /**
     * Handles the HostNebulaDeployedEvent.
     * This event is triggered when Nebula is successfully deployed specifically to
     * the host machine.
     * It's a key point to trigger Docker Swarm initialization.
     * 
     * @param event The HostNebulaDeployedEvent
     */
    @EventListener
    public void handleHostNebulaDeployed(HostNebulaDeployedEvent event) {
        logger.info("Received HostNebulaDeployedEvent. Interface verified: {}", event.isInterfaceVerified());

        HostServer hostServer = event.getHostServer();
        if (hostServer == null) {
            logger.warn("Host server is null in HostNebulaDeployedEvent");
            return;
        }

        logger.info("Nebula deployed to host server: {}, interface verified: {}",
                hostServer.getId(), event.isInterfaceVerified());

        // Mark the host server as having Nebula deployed if not already marked
        if (!hostServer.isNebulaDeployed()) {
            hostServerService.markNebulaDeployed(hostServer);
            logger.info("Marked host server as having Nebula deployed");
        }

        // Skip Docker Swarm initialization if this host is a lighthouse
        if (hostServer.getVpn() != null && hostServer.getVpn().getLighthouse()) {
            logger.info("Host server is a lighthouse, skipping Docker Swarm initialization");
            return;
        }

        // Check if Docker Swarm is already initialized
        try {
            String swarmCheckCmd = "docker info | grep 'Swarm: active' || echo 'SWARM_NOT_ACTIVE'";
            Process swarmCheck = Runtime.getRuntime().exec(swarmCheckCmd);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(swarmCheck.getInputStream()))) {
                String swarmResult = reader.lines().collect(Collectors.joining("\n"));

                if (swarmResult.contains("SWARM_NOT_ACTIVE")) {
                    logger.info("Docker Swarm not active. Initializing host as Swarm manager...");
                    initializeDockerSwarmWithRetry(hostServer);
                } else {
                    logger.info("Docker Swarm already active. Host is ready to accept workers.");
                    // Make sure swarmManager flag is set
                    if (!hostServer.isSwarmManager()) {
                        hostServer.setSwarmManager(true);
                        hostServerService.save(hostServer);
                        logger.info("Updated host server to be marked as swarm manager");
                    }

                    // Register the host server as a swarm node using the central method
                    dockerSwarmService.registerHostSwarmNode(hostServer);

                    initialized.set(true);
                    initializationLatch.countDown();
                }
            }
        } catch (Exception e) {
            logger.warn("Error checking Docker Swarm status: {}", e.getMessage());
            // Try to initialize swarm anyway
            initializeDockerSwarmWithRetry(hostServer);
        }
    }

    /**
     * Handles the LighthouseNebulaDeployedEvent.
     * This event is triggered when a lighthouse Nebula is successfully deployed.
     * We use this to trigger the host Nebula deployment if it hasn't happened yet,
     * then initialize the host as the Docker Swarm manager.
     * 
     * @param event The LighthouseNebulaDeployedEvent
     */
    @EventListener
    public void handleLighthouseDeployed(LighthouseNebulaDeployedEvent event) {
        logger.info("Lighthouse Nebula deployed event received from: {}. Source object type: {}",
                event.getSource().getClass().getSimpleName(),
                event.getSource().toString());

        // Log information about the deployed lighthouse
        Nebula lighthouse = event.getNebula();
        if (lighthouse != null) {
            logger.info("Lighthouse configuration - IP: {}, Lighthouse flag: {}, ID: {}",
                    lighthouse.getIp(), lighthouse.getLighthouse(), lighthouse.getId());
        }

        Optional<HostServer> hostServerOpt = hostServerService.findFirst();
        if (hostServerOpt.isPresent()) {
            HostServer hostServer = hostServerOpt.get();
            logger.info("Found host server: {}. Host Nebula deployed: {}",
                    hostServer.getId(), hostServer.isNebulaDeployed());

            // Even if the host is a lighthouse (which is unusual), we need to make sure the
            // host
            // has Nebula running so it can communicate with other nodes
            boolean nebulaWorking = hostServer.isNebulaDeployed() &&
                    isNebulaInterfaceUpAndRunning(hostServer.getVpn().getIp());

            if (nebulaWorking) {
                logger.info("Host already has Nebula deployed and working. Checking Docker Swarm...");

                // Check if Docker Swarm is already initialized
                try {
                    String swarmCheckCmd = "docker info | grep 'Swarm: active' || echo 'SWARM_NOT_ACTIVE'";
                    Process swarmCheck = Runtime.getRuntime().exec(swarmCheckCmd);
                    try (BufferedReader reader = new BufferedReader(
                            new InputStreamReader(swarmCheck.getInputStream()))) {
                        String swarmResult = reader.lines().collect(Collectors.joining("\n"));

                        if (swarmResult.contains("SWARM_NOT_ACTIVE")) {
                            logger.info("Docker Swarm not active. Initializing host as Swarm manager...");
                            initializeDockerSwarmWithRetry(hostServer);
                        } else {
                            logger.info("Docker Swarm already active. Host is ready to accept workers.");
                            initialized.set(true);
                            initializationLatch.countDown();
                        }
                    }
                } catch (Exception e) {
                    logger.warn("Error checking Docker Swarm status: {}", e.getMessage());
                }

                return;
            }

            // Ensure the host has the correct Nebula configuration to use this lighthouse
            final HostServer updatedHostServer = ensureHostUsesLighthouse(hostServer, event.getNebula());
            logger.info("Host server updated to use lighthouse. Host VPN ID: {}",
                    updatedHostServer.getVpn() != null ? updatedHostServer.getVpn().getId() : "null");

            // Deploy Nebula and initialize Docker Swarm as a clear sequence of steps
            logger.info("Deploying Nebula to host after lighthouse deployment...");

            deployNebulaToHostWithVerification(updatedHostServer)
                    .thenApply(result -> {
                        if (!result) {
                            logger.error("Failed to deploy Nebula to host after lighthouse deployment");
                            initializationLatch.countDown();
                            return false;
                        }

                        logger.info(
                                "Nebula deployed successfully to host! Now initializing host as Docker Swarm manager...");
                        initializeDockerSwarmWithRetry(updatedHostServer);
                        return true;
                    })
                    .whenComplete((result, ex) -> {
                        if (ex != null) {
                            logger.error("Failed in host initialization after lighthouse deployment", ex);
                        } else if (Boolean.TRUE.equals(result)) {
                            logger.info("Host initialization completed successfully! Host is ready as Swarm manager.");
                            initialized.set(true);
                        } else {
                            logger.error("Host initialization failed after lighthouse deployment");
                        }
                        initializationLatch.countDown();
                    });
        } else {
            logger.warn("No host server found when lighthouse deployed event was received.");
            initializationLatch.countDown();
        }
    }

    /**
     * Gets the existing host server or creates a new one.
     * 
     * @return The host server entity
     */
    private HostServer getOrCreateHostServer() {
        Optional<HostServer> hostServerOpt = hostServerService.findFirst();
        if (hostServerOpt.isPresent()) {
            return hostServerOpt.get();
        }

        logger.info("Creating new host server entity");
        return hostServerService.createHostServer();
    }

    /**
     * Creates a Nebula configuration for the host machine.
     * The host is configured as a regular node (not a lighthouse)
     * that connects to an existing lighthouse.
     * 
     * @return The created Nebula configuration
     */
    private Nebula createNebulaConfigForHost() {
        // First, check if we have any existing lighthouse configurations
        List<Nebula> lighthouses = nebulaService.getAllLighthouseConfigs();

        if (lighthouses.isEmpty()) {
            // If no lighthouse exists, we need to create one first
            logger.info("No existing lighthouse found. Creating a lighthouse configuration first.");
            NebulaConfigurationDTO lighthouseConfig = new NebulaConfigurationDTO();
            lighthouseConfig.setLighthouse(true);
            lighthouseConfig.setIp("10.0.0.1");
            lighthouseConfig.setSubnet(24);

            // Initialize the sets before adding elements
            Set<String> lighthouseRoles = new HashSet<>();
            lighthouseRoles.add("lighthouse");
            lighthouseConfig.setRoles(lighthouseRoles);

            Set<String> lighthouseAllowedCIDRs = new HashSet<>();
            lighthouseAllowedCIDRs.add("10.0.0.0/24");
            lighthouseConfig.setAllowedCIDRs(lighthouseAllowedCIDRs);

            Set<String> lighthouseAllowedRoles = new HashSet<>();
            lighthouseAllowedRoles.add("host");
            lighthouseAllowedRoles.add("swarm_manager");
            lighthouseAllowedRoles.add("swarm_worker");
            lighthouseAllowedRoles.add("containers");
            lighthouseConfig.setAllowedRoles(lighthouseAllowedRoles);

            Nebula lighthouse = nebulaService.createNebulaConfig(lighthouseConfig);
            logger.info("Created lighthouse configuration with ID: {}", lighthouse.getId());

            // Now create the host configuration
            NebulaConfigurationDTO hostConfig = new NebulaConfigurationDTO();
            hostConfig.setLighthouse(false);
            hostConfig.setLighthouseId(lighthouse.getId()); // Use the lighthouse ID we just created

            // Initialize the sets before adding elements
            Set<String> roles = new HashSet<>();
            roles.add("host");
            roles.add("swarm_manager");
            hostConfig.setRoles(roles);

            Set<String> allowedCIDRs = new HashSet<>();
            allowedCIDRs.add("10.0.0.0/24");
            hostConfig.setAllowedCIDRs(allowedCIDRs);

            Set<String> allowedRoles = new HashSet<>();
            allowedRoles.add("lighthouse");
            allowedRoles.add("swarm_worker");
            allowedRoles.add("containers");
            hostConfig.setAllowedRoles(allowedRoles);

            return nebulaService.createNebulaConfig(hostConfig);
        } else {
            // Use the first lighthouse we found
            Nebula lighthouse = lighthouses.get(0);
            logger.info("Using existing lighthouse with ID: {}", lighthouse.getId());

            NebulaConfigurationDTO hostConfig = new NebulaConfigurationDTO();
            hostConfig.setLighthouse(false);
            hostConfig.setLighthouseId(lighthouse.getId()); // Use the existing lighthouse ID

            // Initialize the sets before adding elements
            Set<String> roles = new HashSet<>();
            roles.add("host");
            roles.add("swarm_manager");
            hostConfig.setRoles(roles);

            Set<String> allowedCIDRs = new HashSet<>();
            allowedCIDRs.add("10.0.0.0/24");
            hostConfig.setAllowedCIDRs(allowedCIDRs);

            Set<String> allowedRoles = new HashSet<>();
            allowedRoles.add("lighthouse");
            allowedRoles.add("swarm_worker");
            allowedRoles.add("containers");
            hostConfig.setAllowedRoles(allowedRoles);

            return nebulaService.createNebulaConfig(hostConfig);
        }
    }

    /**
     * Waits for the host initialization to complete.
     * 
     * @param timeoutSeconds Maximum time to wait in seconds
     * @return true if initialization completed successfully, false if it timed out
     */
    public boolean waitForInitialization(int timeoutSeconds) {
        try {
            boolean completed = initializationLatch.await(timeoutSeconds, TimeUnit.SECONDS);
            return completed && initialized.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("Interrupted while waiting for host initialization", e);
            return false;
        }
    }

    /**
     * Checks if there are any servers with deployed lighthouse Nebula
     * configurations.
     * 
     * @return true if a deployed lighthouse exists, false otherwise
     */
    private boolean checkForDeployedLighthouse() {
        try {
            // Get all servers from the repository
            List<Server> servers = serverRepository.findAll();

            // Check if any server has a deployed lighthouse Nebula
            for (Server server : servers) {
                // Skip servers without VPN configuration
                if (server.getVpn() == null) {
                    continue;
                }

                // Check if this server has a lighthouse Nebula
                // Since Server doesn't have isNebulaDeployed(), we'll check if the VPN is
                // configured as a lighthouse
                // and assume it's deployed if it exists and is configured as a lighthouse
                if (server.getVpn().getLighthouse()) {
                    logger.info("Found lighthouse on server: {}", server.getId());
                    return true;
                }
            }

            // Also check the host server if it has a deployed lighthouse
            Optional<HostServer> hostServerOpt = hostServerService.findFirst();
            if (hostServerOpt.isPresent()) {
                HostServer hostServer = hostServerOpt.get();
                if (hostServer.getVpn() != null &&
                        hostServer.getVpn().getLighthouse() &&
                        hostServer.isNebulaDeployed()) {
                    logger.info("Found deployed lighthouse on host server");
                    return true;
                }
            }

            logger.info("No deployed lighthouse found among {} servers", servers.size());
            return false;
        } catch (Exception e) {
            logger.error("Error checking for deployed lighthouses", e);
            return false;
        }
    }

    /**
     * Deploy Nebula to the host with verification using the new event-based flow
     * 
     * @param hostServer The host server entity
     * @return CompletableFuture<Boolean> that completes with true if deployment
     *         succeeded, false otherwise
     */
    private CompletableFuture<Boolean> deployNebulaToHostWithVerification(HostServer hostServer) {
        // The NebulaDeploymentService will publish HostNebulaDeployedEvent that we'll
        // handle separately
        return nebulaDeploymentService.deployNebulaToHost(hostServer)
                .thenCompose(v -> {
                    // We'll wait for the interface to be up, but the event will be handled
                    // separately
                    return waitForNebulaInterfaceWithTimeout(hostServer.getVpn().getIp(), 60); // 60 second timeout
                });
    }

    /**
     * Initialize Docker Swarm with retry logic for better reliability
     * 
     * @param hostServer The host server entity
     */
    private void initializeDockerSwarmWithRetry(HostServer hostServer) {
        final int MAX_RETRIES = 3;
        final int RETRY_DELAY_SECONDS = 5;

        logger.info("Initializing Docker Swarm with retry (max attempts: {})", MAX_RETRIES);

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            final int currentAttempt = attempt; // Make a final copy for use in lambda
            try {
                logger.info("Docker Swarm initialization attempt {}/{}", currentAttempt, MAX_RETRIES);

                dockerSwarmService.initializeSwarmOnHost(hostServer)
                        .whenComplete((result, ex) -> {
                            if (ex != null) {
                                logger.error("Failed to initialize Docker Swarm on attempt {}", currentAttempt, ex);
                            } else {
                                logger.info("Docker Swarm initialized successfully on attempt {}", currentAttempt);
                                initialized.set(true);
                                initializationLatch.countDown();
                            }
                        })
                        .get(60, TimeUnit.SECONDS); // Wait for completion with timeout

                // If we get here, initialization was successful
                logger.info("Docker Swarm initialization completed successfully");
                return;

            } catch (Exception e) {
                logger.error("Error during Docker Swarm initialization attempt {}/{}: {}",
                        currentAttempt, MAX_RETRIES, e.getMessage());

                if (currentAttempt < MAX_RETRIES) {
                    try {
                        logger.info("Waiting {} seconds before retry...", RETRY_DELAY_SECONDS * currentAttempt);
                        Thread.sleep(RETRY_DELAY_SECONDS * 1000 * currentAttempt);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        logger.warn("Interrupted while waiting for retry");
                    }
                } else {
                    logger.error("Failed to initialize Docker Swarm after {} attempts", MAX_RETRIES);
                }
            }
        }
    }

    /**
     * Wait for the Nebula interface to be up and running with a timeout
     * 
     * @param expectedIp     The expected IP address for the Nebula interface
     * @param timeoutSeconds Maximum time to wait in seconds
     * @return CompletableFuture<Boolean> that completes with true if the interface
     *         is up, false if it timed out
     */
    private CompletableFuture<Boolean> waitForNebulaInterfaceWithTimeout(String expectedIp, int timeoutSeconds) {
        return CompletableFuture.supplyAsync(() -> {
            logger.info("Waiting for Nebula interface with IP {} to be up (timeout: {}s)...",
                    expectedIp, timeoutSeconds);

            long startTime = System.currentTimeMillis();
            long endTime = startTime + (timeoutSeconds * 1000);

            while (System.currentTimeMillis() < endTime) {
                try {
                    if (isNebulaInterfaceUpAndRunning(expectedIp)) {
                        logger.info("Nebula interface is UP with IP: {}", expectedIp);
                        return true;
                    }

                    // Wait before checking again
                    Thread.sleep(2000);
                } catch (Exception e) {
                    logger.warn("Error checking Nebula interface: {}", e.getMessage());
                    // Continue trying until timeout
                }
            }

            logger.warn("Timed out waiting for Nebula interface to be up with IP: {}", expectedIp);
            return false;
        });
    }

    /**
     * Check if the Nebula interface is up and running with the expected IP
     * 
     * @param expectedIp The expected IP address
     * @return true if the interface is up and running, false otherwise
     */
    private boolean isNebulaInterfaceUpAndRunning(String expectedIp) {
        try {
            // Check if the Nebula process is running
            String processCmd = "pgrep -f '/usr/local/bin/nebula' || echo 'NOT_RUNNING'";
            Process processCheck = Runtime.getRuntime().exec(processCmd);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(processCheck.getInputStream()))) {
                String processResult = reader.lines().collect(Collectors.joining("\n"));

                if (processResult.contains("NOT_RUNNING")) {
                    logger.warn("Nebula process is not running");
                    return false;
                }
            }

            // Check if the interface exists and has the correct IP
            String interfaceCmd = "ip addr show nebula1 || echo 'INTERFACE_NOT_FOUND'";
            Process interfaceCheck = Runtime.getRuntime().exec(interfaceCmd);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(interfaceCheck.getInputStream()))) {
                String interfaceResult = reader.lines().collect(Collectors.joining("\n"));

                logger.debug("Full interface output: [{}]", interfaceResult);

                if (interfaceResult.contains("INTERFACE_NOT_FOUND")) {
                    logger.warn("Nebula interface not found");
                    return false;
                }

                // Extract just the IP part without CIDR notation if present
                String plainExpectedIp = expectedIp.split("/")[0].trim();
                logger.debug("Looking for IP: [{}]", plainExpectedIp);

                // More flexible state check - if the interface exists, consider it operational
                boolean isUp = true; // If we got here, interface exists, which is primary requirement

                // Attempt multiple detection methods in sequence
                boolean hasCorrectIp = false;

                // Method 1: Very basic pattern - just look for "inet X.X.X.X"
                if (interfaceResult.contains("inet " + plainExpectedIp)) {
                    logger.debug("Found IP using basic 'inet X.X.X.X' check");
                    hasCorrectIp = true;
                }
                // Method 2: Use grep directly which is more reliable
                else {
                    try {
                        String grepCmd = "ip addr show nebula1 | grep -o 'inet " + plainExpectedIp + "[^ ]*'";
                        Process grepCheck = Runtime.getRuntime().exec(grepCmd);
                        try (BufferedReader grepReader = new BufferedReader(
                                new InputStreamReader(grepCheck.getInputStream()))) {
                            String grepResult = grepReader.lines().collect(Collectors.joining("\n"));
                            logger.debug("Grep result: [{}]", grepResult);
                            if (!grepResult.isEmpty() && grepResult.contains(plainExpectedIp)) {
                                logger.debug("Found IP using grep check");
                                hasCorrectIp = true;
                            }
                        }
                    } catch (Exception e) {
                        logger.warn("Error running grep check: {}", e.getMessage());
                    }
                }

                // Method 3: Last resort - simple contains check
                if (!hasCorrectIp && interfaceResult.contains(plainExpectedIp)) {
                    logger.debug("Found IP using simple contains check");
                    hasCorrectIp = true;
                }

                if (!hasCorrectIp) {
                    logger.warn("Nebula interface does not have the expected IP: {}", plainExpectedIp);
                    logger.debug("Interface output: [{}]", interfaceResult);
                } else {
                    logger.info("Nebula interface exists with correct IP: {}", plainExpectedIp);
                }

                // Log the actual state for debugging
                if (interfaceResult.contains("state UP")) {
                    logger.info("Nebula interface state is UP");
                } else if (interfaceResult.contains("state UNKNOWN")) {
                    logger.info("Nebula interface state is UNKNOWN (still considered operational)");
                } else {
                    logger.info("Nebula interface state might be non-standard, but interface exists");
                }

                // As long as interface exists and has correct IP, consider it working
                return isUp && hasCorrectIp;
            }
        } catch (Exception e) {
            logger.error("Error checking Nebula interface and process", e);
            return false;
        }
    }

    /**
     * Ensure the host server is configured to use the specified lighthouse
     * 
     * @param hostServer The host server entity
     * @param lighthouse The lighthouse Nebula configuration
     * @return The updated host server
     */
    private HostServer ensureHostUsesLighthouse(HostServer hostServer, Nebula lighthouse) {
        // Check if we need to update the host's Nebula config
        if (hostServer.getVpn() == null ||
                (hostServer.getVpn().getLighthouseIps() == null || hostServer.getVpn().getLighthouseIps().isEmpty())) {

            logger.info("Updating host Nebula configuration to use lighthouse: {}", lighthouse.getId());

            // Create or update the host's Nebula config to use this lighthouse
            NebulaConfigurationDTO hostConfig = new NebulaConfigurationDTO();
            hostConfig.setLighthouse(false);
            hostConfig.setLighthouseId(lighthouse.getId());

            // Initialize the sets before adding elements
            Set<String> roles = new HashSet<>();
            roles.add("host");
            roles.add("swarm_manager");
            hostConfig.setRoles(roles);

            Set<String> allowedCIDRs = new HashSet<>();
            allowedCIDRs.add("10.0.0.0/24");
            hostConfig.setAllowedCIDRs(allowedCIDRs);

            Set<String> allowedRoles = new HashSet<>();
            allowedRoles.add("lighthouse");
            allowedRoles.add("swarm_worker");
            allowedRoles.add("containers");
            hostConfig.setAllowedRoles(allowedRoles);

            Nebula updatedConfig = nebulaService.createNebulaConfig(hostConfig);
            return hostServerService.setNebulaConfig(hostServer, updatedConfig);
        }

        return hostServer;
    }
}