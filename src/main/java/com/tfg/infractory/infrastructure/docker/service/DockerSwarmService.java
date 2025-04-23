package com.tfg.infractory.infrastructure.docker.service;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Optional;
import java.util.HashMap;
import org.slf4j.Logger;
import java.io.IOException;
import java.io.BufferedReader;
import org.slf4j.LoggerFactory;
import java.io.InputStreamReader;
import org.springframework.stereotype.Service;
import com.github.dockerjava.api.DockerClient;
import com.tfg.infractory.domain.model.Instance;
import com.tfg.infractory.domain.model.DockerConfig;
import com.tfg.infractory.domain.model.HostServer;
import com.github.dockerjava.api.model.ServiceSpec;
import org.springframework.beans.factory.annotation.Autowired;
import com.github.dockerjava.api.command.CreateServiceResponse;
import com.tfg.infractory.domain.repository.InstanceRepository;
import com.tfg.infractory.infrastructure.local.LocalProviderService;
import com.tfg.infractory.infrastructure.nebula.service.NebulaService;
import com.tfg.infractory.infrastructure.ssh.model.SSHKey;
import com.tfg.infractory.infrastructure.ssh.service.RemoteCommandService;
import org.springframework.context.ApplicationEventPublisher;
import com.tfg.infractory.web.event.ApplyDockerConfigEvent;
import com.tfg.infractory.domain.service.HostServerService;
import com.tfg.infractory.infrastructure.docker.exception.SwarmInitializationException;

import org.springframework.context.event.EventListener;
import com.tfg.infractory.domain.model.Server;
import org.springframework.beans.factory.annotation.Value;
import com.github.dockerjava.api.model.TaskSpec;
import com.github.dockerjava.api.model.ServicePlacement;
import com.tfg.infractory.domain.repository.ServerRepository;
import com.tfg.infractory.web.event.ServerCreatedEvent;
import org.springframework.transaction.annotation.Transactional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import com.tfg.infractory.web.event.SwarmManagerInitializedEvent;
import com.tfg.infractory.domain.model.SwarmNode;
import com.tfg.infractory.domain.repository.SwarmNodeRepository;
import java.util.stream.Collectors;
import com.tfg.infractory.web.event.NebulaDeployedEvent;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;
import com.tfg.infractory.infrastructure.nebula.service.NebulaDeploymentService;

@Service
public class DockerSwarmService {

    private static final Logger logger = LoggerFactory.getLogger(DockerSwarmService.class);
    private final DockerClient dockerClient;
    private final RemoteCommandService remoteCommandService;
    private final InstanceRepository instanceRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final ServerRepository serverRepository;
    private final HostServerService hostServerService;
    private final ExecutorService executorService;
    @Value("${docker.install.timeout:300}")
    private int dockerInstallTimeout;

    @Value("${docker.command.timeout:30}")
    private int dockerCommandTimeout;

    @Value("${docker.ssh.user:root}")
    private String sshUser;

    private final SwarmNodeRepository swarmNodeRepository;

    @Autowired
    private NebulaService nebulaService;

    @Autowired
    public DockerSwarmService(DockerClient dockerClient,
            RemoteCommandService remoteCommandService,
            InstanceRepository instanceRepository,
            LocalProviderService localProviderService,
            NebulaService nebulaService,
            ApplicationEventPublisher eventPublisher,
            ServerRepository serverRepository,
            HostServerService hostServerService,
            ExecutorService executorService,
            org.springframework.context.ApplicationContext applicationContext,
            SwarmNodeRepository swarmNodeRepository) {
        this.dockerClient = dockerClient;
        this.remoteCommandService = remoteCommandService;
        this.instanceRepository = instanceRepository;
        this.eventPublisher = eventPublisher;
        this.serverRepository = serverRepository;
        this.hostServerService = hostServerService;
        this.executorService = executorService;
        this.swarmNodeRepository = swarmNodeRepository;
    }

    public void initializeSwarm(Server server) {
        // Skip servers configured as lighthouses
        if (server.getVpn() != null && server.getVpn().getLighthouse()) {
            logger.info("Skipping swarm initialization for server: {} because it's configured as a lighthouse",
                    server.getId());
            return;
        }

        if (server.getVpn() == null || server.getVpn().getIp() == null) {
            throw new IllegalStateException("Nebula must be configured before Swarm initialization");
        }

        Instance instance = server.getInstance();
        SSHKey sshKey = instance.getSshKey();

        try {
            // We no longer use per-instance swarm manager approach
            // Always join the host swarm instead
            joinExistingSwarm(instance, sshKey);
        } catch (Exception e) {
            logger.error("Failed to initialize/join swarm for server: {}", server.getId(), e);
            throw new SwarmJoinException("Failed to initialize/join swarm", e);
        }
    }

    /**
     * Makes an instance join an existing Docker Swarm.
     * This method retrieves the swarm manager's Nebula IP (which is now the host)
     * and makes the instance join the swarm using that IP.
     * If no swarm is initialized yet on the host, it will initialize it first.
     * 
     * @param instance The instance to join the swarm
     * @param sshKey   The SSH key for the instance
     * @throws Exception If joining the swarm fails
     */
    private void joinExistingSwarm(Instance instance, SSHKey sshKey) throws Exception {
        // Find the host server (swarm manager)
        Optional<HostServer> hostServerOpt = hostServerService.findFirst();
        if (hostServerOpt.isEmpty() || hostServerOpt.get().getVpn() == null) {
            throw new IllegalStateException("No host swarm manager found or host's Nebula not configured");
        }

        HostServer hostServer = hostServerOpt.get();
        String managerNebulaIp = hostServer.getVpn().getIp();

        if (managerNebulaIp == null || managerNebulaIp.isEmpty()) {
            throw new IllegalStateException("Host swarm manager's Nebula IP is not configured");
        }

        // Verify the manager's Nebula IP is accessible
        verifyManagerNebulaIp(managerNebulaIp);

        // Check if swarm is already initialized yet on the host
        boolean swarmInitialized = isSwarmAlreadyInitializedOnHost();

        // If not initialized, initialize it now
        if (!swarmInitialized) {
            logger.info("Docker Swarm not initialized on host yet. Initializing before joining...");
            try {
                // Extract just the IP part without CIDR notation if present
                String plainNebulaIp = managerNebulaIp.split("/")[0].trim();

                // Initialize swarm on the host
                String initCommand = String.format(
                        "docker swarm init --advertise-addr %s:2377 --listen-addr %s:2377",
                        plainNebulaIp, plainNebulaIp);

                logger.info("Executing swarm init command on host: {}", initCommand);

                // Use a shell to execute the command
                ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", initCommand);
                pb.redirectErrorStream(true);
                Process process = pb.start();

                StringBuilder output = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\n");
                        logger.info("STDOUT: {}", line);
                    }
                }

                int exitCode = process.waitFor();
                String result = output.toString();

                if (exitCode != 0) {
                    logger.warn("Swarm initialization reported exit code {}: {}", exitCode, result);

                    // Check if this is just because the Swarm is already initialized
                    if (result.contains("this node is already part of a swarm") ||
                            result.contains("already part of a swarm")) {
                        logger.info("Docker Swarm is already initialized - proceeding with join");
                    } else {
                        throw new SwarmInitializationException("Failed to initialize Docker Swarm on host: " + result);
                    }
                } else {
                    logger.info("Successfully initialized Docker Swarm on host");

                    // Update host server status
                    hostServer.setSwarmManager(true);
                    hostServerService.save(hostServer);

                    // Directly register the host node in the database using the central method
                    registerHostSwarmNode(hostServer);

                    // Publish event for successful initialization
                    logger.info("Publishing SwarmManagerInitializedEvent for newly initialized host");
                    eventPublisher.publishEvent(new SwarmManagerInitializedEvent(this, hostServer));

                    // Give Docker a moment to fully initialize the swarm before joining
                    Thread.sleep(3000);
                }
            } catch (SwarmInitializationException e) {
                // This is a specific swarm initialization error - rethrow it
                throw e;
            } catch (Exception e) {
                logger.error("Error initializing Docker Swarm on host", e);
                throw new SwarmInitializationException("Failed to initialize Docker Swarm on host", e);
            }
        }

        // Now that we've ensured the swarm is initialized, proceed with joining
        String joinToken = getWorkerJoinToken();

        String result;
        if (instance.getType().equalsIgnoreCase("local")) {
            result = joinLocalContainerToSwarm(instance, joinToken, managerNebulaIp);
        } else {
            result = joinRemoteInstanceToSwarm(instance, sshKey, joinToken, managerNebulaIp);
        }

        if (result.contains("Error") || result.contains("Failed")) {
            throw new SwarmJoinException("Failed to join swarm: " + result, null);
        }
    }

    /**
     * Verifies that the manager's Nebula IP is accessible.
     * Enhanced to be more flexible - only requires the Nebula interface to exist
     * with correct IP
     * when the swarm is not yet initialized.
     * 
     * @param managerNebulaIp The Nebula IP of the swarm manager
     * @throws IllegalStateException If the manager's Nebula IP is not accessible
     *                               after all retries
     */
    private void verifyManagerNebulaIp(String managerNebulaIp) {
        final int MAX_ATTEMPTS = 3;
        final int INITIAL_DELAY_SECONDS = 2;

        // Check if swarm is already initialized
        boolean swarmInitialized = isSwarmAlreadyInitializedOnHost();

        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                logger.info("Verifying manager's Nebula IP: {} (attempt {}/{})", managerNebulaIp, attempt,
                        MAX_ATTEMPTS);

                // Check if the Nebula interface exists
                String checkNebulaInterface = "ip addr show nebula1";
                try {
                    String result = executeLocalCommand(checkNebulaInterface);

                    // Extract plain IP from potentially CIDR-notated IP
                    String plainIp = managerNebulaIp.split("/")[0].trim();

                    // Check if interface exists and has the right IP
                    boolean interfaceExists = !result.contains("does not exist") && result.contains("nebula1");
                    boolean hasCorrectIp = result.contains("inet " + plainIp);
                    boolean isUp = result.contains("<") && result.contains("UP") && result.contains(">");

                    if (interfaceExists && hasCorrectIp && isUp) {
                        logger.info("Nebula interface exists with the correct IP and is UP");

                        // If swarm is not initialized yet, we don't need to check port connectivity
                        if (!swarmInitialized) {
                            logger.info(
                                    "Swarm not initialized yet, accepting interface verification without port check");
                            return; // Interface exists with right IP, that's enough for now
                        }

                        // Only check port if swarm is already initialized
                        try {
                            String telnetCommand = "nc -z -v -w 2 " + plainIp + " 2377";
                            String ncResult = executeLocalCommand(telnetCommand);

                            if (ncResult.contains("succeeded") || ncResult.contains("open")) {
                                logger.info("Docker Swarm port is accessible on manager's Nebula IP");
                                return; // Success!
                            } else {
                                logger.warn("Docker Swarm port is not accessible on manager's Nebula IP. Result: {}",
                                        ncResult);
                            }
                        } catch (Exception e) {
                            logger.warn("Failed to check Docker Swarm port: {}", e.getMessage());
                        }
                    } else {
                        if (!interfaceExists) {
                            logger.warn("Nebula interface does not exist");
                        } else if (!hasCorrectIp) {
                            logger.warn("Nebula interface exists but doesn't have the right IP {}", plainIp);
                        } else if (!isUp) {
                            logger.warn("Nebula interface exists with right IP but is not UP");
                        }
                    }
                } catch (Exception e) {
                    logger.warn("Failed to check Nebula interface: {}", e.getMessage());
                }

                // If we're not at the last attempt, wait before retrying with increasing delay
                if (attempt < MAX_ATTEMPTS) {
                    int delaySeconds = INITIAL_DELAY_SECONDS * attempt; // Increasing delay
                    logger.info("Waiting {} seconds before next verification attempt...", delaySeconds);
                    Thread.sleep(delaySeconds * 1000);
                }
            } catch (Exception e) {
                logger.error("Error in verification attempt {}", attempt, e);
            }
        }

        // We'll proceed even if verification fails, but log a warning
        logger.warn(
                "Proceeding with Docker Swarm operations despite failing to verify Nebula connection after {} attempts",
                MAX_ATTEMPTS);
    }

    @EventListener
    public void handleServerCreated(ServerCreatedEvent event) {
        Server server = event.getServer();

        logger.info("Handling ServerCreatedEvent for server: {} with VPN config: {}",
                server.getId(),
                server.getVpn() != null ? (server.getVpn().getLighthouse() ? "Lighthouse" : "Non-Lighthouse") : "None");

        // Skip swarm initialization for servers configured as lighthouses
        if (server.getVpn() != null && server.getVpn().getLighthouse()) {
            logger.info("Skipping swarm initialization for server: {} because it's configured as a lighthouse",
                    server.getId());
            return;
        }

        // Check if both Nebula is configured and the lighthouse is running
        if (server.getVpn() != null && server.getVpn().getIp() != null) {
            // Run in a separate thread to avoid blocking the event listener
            CompletableFuture.runAsync(() -> {
                try {
                    // Check if lighthouse is deployed and running
                    boolean lighthouseRunning = isLighthouseRunning();
                    if (!lighthouseRunning) {
                        logger.warn("Lighthouse is not running, delaying swarm initialization for server: {}",
                                server.getId());
                        return;
                    }

                    // Check if host Nebula interface is up and running with the correct IP
                    boolean hostNebulaRunning = isHostNebulaRunning();
                    if (!hostNebulaRunning) {
                        logger.warn("Host Nebula is not running, delaying swarm initialization for server: {}",
                                server.getId());
                        return;
                    }

                    logger.info(
                            "Both host and lighthouse Nebula are running, proceeding with swarm initialization for server: {}",
                            server.getId());
                    initializeSwarm(server);
                } catch (Exception e) {
                    logger.error("Failed to initialize swarm for server: {}", server.getId(), e);
                }
            }, executorService);
        } else {
            logger.info("Waiting for Nebula configuration before initializing swarm for server: {}", server.getId());
        }
    }

    /**
     * Checks if the lighthouse is deployed and running.
     * This method looks for any server configured as a lighthouse
     * and verifies that its Nebula instance is running.
     * 
     * @return true if a lighthouse is running, false otherwise
     */
    private boolean isLighthouseRunning() {
        try {
            // First check if any server is configured as a lighthouse
            List<Server> servers = serverRepository.findAll();

            // Check regular servers
            for (Server server : servers) {
                if (server.getVpn() != null && server.getVpn().getLighthouse()) {
                    logger.info("Found lighthouse configuration on server: {}", server.getId());

                    // Check if server's Nebula is actually deployed
                    if (isServerNebulaRunning(server)) {
                        logger.info("Lighthouse on server {} is running", server.getId());
                        return true;
                    }
                }
            }

            // Check host server
            HostServer hostServer = hostServerService.findFirst().orElse(null);
            if (hostServer != null &&
                    hostServer.getVpn() != null &&
                    hostServer.getVpn().getLighthouse() &&
                    hostServer.isNebulaDeployed()) {

                // Additional check to see if Nebula is actually running on host
                if (isNebulaProcessRunningOnHost()) {
                    logger.info("Lighthouse on host server is running");
                    return true;
                }
            }

            logger.warn("No running lighthouse found");
            return false;
        } catch (Exception e) {
            logger.error("Error checking if lighthouse is running", e);
            return false;
        }
    }

    /**
     * Checks if a server's Nebula is running.
     * For remote servers, this checks if the server is in RUNNING state,
     * which implies Nebula is deployed and running.
     * 
     * @param server The server to check
     * @return true if the server's Nebula is running, false otherwise
     */
    private boolean isServerNebulaRunning(Server server) {
        if (server.getInstance() == null) {
            return false;
        }

        Instance instance = server.getInstance();

        // For local instances, we need to check the container
        if (instance.getType().equalsIgnoreCase("local")) {
            return isNebulaRunningInContainer(instance.getProviderId());
        }

        // For remote instances, if they're RUNNING, we assume Nebula is also running
        // since Nebula should be deployed automatically when server is created
        return Instance.InstanceStatus.RUNNING.equals(instance.getStatus());
    }

    /**
     * Checks if the Nebula process is running in a container.
     * 
     * @param containerId The container ID
     * @return true if Nebula is running in the container, false otherwise
     */
    private boolean isNebulaRunningInContainer(String containerId) {
        try {
            String[] command = {
                    "docker", "exec", containerId,
                    "pgrep", "-f", "/usr/local/bin/nebula"
            };

            Process process = Runtime.getRuntime().exec(command);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String result = reader.readLine();
                return result != null && !result.isEmpty();
            }
        } catch (Exception e) {
            logger.warn("Error checking if Nebula is running in container {}: {}", containerId, e.getMessage());
            return false;
        }
    }

    /**
     * Checks if the host's Nebula interface is up and running.
     * 
     * @return true if the host's Nebula is running, false otherwise
     */
    private boolean isHostNebulaRunning() {
        try {
            // Check if Nebula process is running on host
            if (!isNebulaProcessRunningOnHost()) {
                return false;
            }

            // Get the host server
            HostServer hostServer = hostServerService.findFirst().orElse(null);
            if (hostServer == null || hostServer.getVpn() == null) {
                logger.warn("Host server not found or not configured with Nebula");
                return false;
            }

            // Get expected Nebula IP
            String expectedIp = hostServer.getVpn().getIp();
            if (expectedIp == null || expectedIp.isEmpty()) {
                logger.warn("Host server Nebula IP not configured");
                return false;
            }

            // Check if Nebula interface is up and has the correct IP
            return isNebulaInterfaceUp(expectedIp);
        } catch (Exception e) {
            logger.error("Error checking if host Nebula is running", e);
            return false;
        }
    }

    /**
     * Checks if the Nebula interface is up and has the correct IP.
     * Enhanced to properly detect interfaces with UP flags even if their state is
     * UNKNOWN.
     * 
     * @param expectedIp The expected IP address
     * @return true if the interface exists with the correct IP, false otherwise
     */
    private boolean isNebulaInterfaceUp(String expectedIp) {
        try {
            // Extract just the IP part without CIDR notation if present
            String plainExpectedIp = expectedIp.split("/")[0].trim();
            logger.debug("Checking for Nebula interface with plain IP: {}", plainExpectedIp);

            // Use a shell to properly execute the command
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "ip addr show nebula1");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            int exitCode = process.waitFor();
            if (exitCode != 0) {
                logger.warn("Nebula interface not found on host");
                return false;
            }

            String result = output.toString();

            // Check for UP flags regardless of interface state
            boolean isUp = result.contains("nebula1")
                    && (result.contains("<") && result.contains("UP") && result.contains(">"));

            // Check if has correct IP address
            boolean hasCorrectIp = result.contains("inet " + plainExpectedIp);

            if (isUp) {
                if (result.contains("state UP")) {
                    logger.info("Nebula interface state is UP");
                } else if (result.contains("state UNKNOWN")) {
                    logger.info("Nebula interface state is UNKNOWN but has UP flags (normal for TUN interfaces)");
                } else {
                    logger.info("Nebula interface has non-standard state but has UP flags");
                }
            } else {
                logger.warn("Nebula interface is not UP according to interface flags");
            }

            if (hasCorrectIp) {
                logger.info("Nebula interface has the correct IP: {}", plainExpectedIp);
            } else {
                logger.warn("Nebula interface does not have the expected IP: {}", plainExpectedIp);
                logger.debug("Interface output: {}", result);
            }

            if (isUp && hasCorrectIp) {
                // Extra verification - try to ping localhost through the interface
                try {
                    ProcessBuilder pingPb = new ProcessBuilder("/bin/sh", "-c", "ping -c 1 -I nebula1 127.0.0.1");
                    pingPb.redirectErrorStream(true);
                    Process pingProcess = pingPb.start();

                    if (pingProcess.waitFor() == 0) {
                        logger.info("Nebula interface is responsive to ping");
                    } else {
                        logger.warn("Nebula interface does not respond to ping, but may still be functional");
                    }
                } catch (Exception e) {
                    logger.warn("Error pinging through Nebula interface: {}", e.getMessage());
                }
            }

            // As long as interface has UP flags and the correct IP, consider it working
            return isUp && hasCorrectIp;
        } catch (Exception e) {
            logger.error("Error checking Nebula interface", e);
            return false;
        }
    }

    /**
     * Checks if the Nebula process is running on the host.
     * Fixed to avoid shell interpretation issues with commands.
     * 
     * @return true if the Nebula process is running, false otherwise
     */
    private boolean isNebulaProcessRunningOnHost() {
        try {
            logger.info("Checking if Nebula process is running on host");

            // Using simpler commands that work better through Java's Runtime.exec
            String[] checkCommands = {
                    // Basic process name check - no pipes or redirections
                    "pgrep nebula",
                    // Simple check for process containing nebula
                    "ps -ef | grep nebula",
                    // Check if nebula interface exists
                    "ip a | grep nebula1"
            };

            for (String cmd : checkCommands) {
                try {
                    // Use a shell to properly handle pipes and redirections
                    ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);
                    pb.redirectErrorStream(true);
                    Process process = pb.start();

                    StringBuilder output = new StringBuilder();
                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            output.append(line).append("\n");
                        }
                    }

                    int exitCode = process.waitFor();
                    String result = output.toString().trim();

                    // Log the result for diagnostics
                    logger.debug("Command '{}' result: '{}', exit code: {}", cmd, result, exitCode);

                    // Process found if exit code is 0 and output is not empty
                    if (exitCode == 0 && !result.isEmpty() && !result.contains("grep nebula")) {
                        logger.info("Found Nebula process using command: '{}'", cmd);
                        if (cmd.contains("ip a")) {
                            logger.info("Nebula interface exists, considering process as running");
                        } else {
                            logger.info("Nebula process is running with output: {}", result);
                        }
                        return true;
                    }
                } catch (Exception e) {
                    logger.warn("Error executing command '{}': {}", cmd, e.getMessage());
                    // Continue with next command on failure
                }
            }

            // Also check with a direct file-based approach
            try {
                ProcessBuilder pbPid = new ProcessBuilder("/bin/sh", "-c",
                        "ls -l /proc/*/exe 2>/dev/null | grep -i nebula");
                pbPid.redirectErrorStream(true);
                Process processPid = pbPid.start();

                StringBuilder output = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(processPid.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\n");
                    }
                }

                String result = output.toString().trim();
                if (!result.isEmpty()) {
                    logger.info("Found Nebula process via /proc examination: {}", result);
                    return true;
                }
            } catch (Exception e) {
                logger.warn("Error checking /proc for Nebula: {}", e.getMessage());
            }

            logger.info("No running Nebula process found on host");
            return false;
        } catch (Exception e) {
            logger.error("Error checking if Nebula process is running on host", e);
            return false;
        }
    }

    public String initializeSwarmOnHost() {
        try {
            logger.info("Initializing Docker Swarm on host machine");

            if (isSwarmAlreadyInitializedOnHost()) {
                logger.info("Docker Swarm is already initialized on this host.");
                return "Docker Swarm is already initialized on this host.";
            }

            // Get the swarm manager server to use its Nebula IP
            Server swarmManagerServer = serverRepository.findByIsSwarmManagerTrue();
            if (swarmManagerServer == null || swarmManagerServer.getVpn() == null) {
                String error = "Failed to initialize swarm: Swarm manager's Nebula configuration not found.";
                logger.error(error);
                return error;
            }

            String nebulaIp = swarmManagerServer.getVpn().getIp();
            logger.info("Using Nebula IP for swarm manager: {}", nebulaIp);

            String[] command = {
                    "docker", "swarm", "init",
                    "--advertise-addr", nebulaIp + ":2377",
                    "--listen-addr", nebulaIp + ":2377"
            };

            String result = executeCommand(command);
            if (result.contains("Error") || result.contains("Failed")) {
                logger.error("Failed to initialize swarm: {}", result);
                return result;
            }

            logger.info("Successfully initialized swarm on host");

            // Get the host's swarm node ID and register it using our central method
            Optional<HostServer> hostServerOpt = hostServerService.findFirst();
            if (hostServerOpt.isPresent()) {
                HostServer hostServer = hostServerOpt.get();
                if (registerHostSwarmNode(hostServer)) {
                    logger.info("Successfully registered host as swarm node");
                }
            } else {
                logger.warn("Could not find host server to register as swarm node");
            }

            return result;
        } catch (Exception e) {
            logger.error("Error initializing Docker Swarm on host", e);
            return "Error initializing Docker Swarm: " + e.getMessage();
        }
    }

    /**
     * Initializes Docker Swarm on the host machine.
     * This method is primarily for compatibility with the listener.
     * 
     * @param hostServer The host server to initialize swarm on (the parameter is
     *                   not used but kept for compatibility)
     * @return A CompletableFuture that completes when the initialization is done
     */
    @Transactional
    public CompletableFuture<Void> initializeSwarmOnHost(HostServer hostServer) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String result = initializeSwarmOnHost();

                // If there was an error in initialization, throw an exception
                if (result.contains("Failed") || result.contains("Error")) {
                    throw new SwarmInitializationException("Failed to initialize Docker Swarm on host: " + result);
                }

                return null;
            } catch (Exception e) {
                logger.error("Error initializing Docker Swarm", e);
                throw new SwarmInitializationException("Failed to initialize Docker Swarm", e);
            }
        }, executorService);
    }

    public String joinSwarm(Instance instance, SSHKey sshKey) {
        try {
            // Check if instance is already part of swarm
            String swarmState = checkSwarmState(instance);
            if ("active".equals(swarmState)) {
                logger.info("Instance {} is already part of a swarm", instance.getId());
                return "Instance is already part of a swarm";
            }

            // Find the host server (swarm manager) instead of using instance-based manager
            Optional<HostServer> hostServerOpt = hostServerService.findFirst();
            if (hostServerOpt.isEmpty() || hostServerOpt.get().getVpn() == null) {
                String error = "Failed to join Swarm: Host server not found or Nebula not configured.";
                logger.error(error);
                return error;
            }

            HostServer hostServer = hostServerOpt.get();
            String managerNebulaIp = hostServer.getVpn().getIp();
            if (managerNebulaIp == null || managerNebulaIp.isEmpty()) {
                String error = "Failed to join Swarm: Host server's Nebula IP not configured.";
                logger.error(error);
                return error;
            }

            String joinToken;
            try {
                joinToken = getWorkerJoinToken();
            } catch (Exception e) {
                String error = "Failed to get worker join token: " + e.getMessage();
                logger.error(error, e);
                return error;
            }

            String result;
            if (instance.getType().equalsIgnoreCase("local")) {
                result = joinLocalContainerToSwarm(instance, joinToken, managerNebulaIp);
            } else {
                result = joinRemoteInstanceToSwarm(instance, sshKey, joinToken, managerNebulaIp);
            }

            // If join was successful, update instance status
            if (!result.contains("Error") && !result.contains("Failed")) {
                instance.setStatus(Instance.InstanceStatus.RUNNING);
                instanceRepository.save(instance);
                logger.info("Instance {} status updated to RUNNING after joining swarm", instance.getId());
            }

            return result;
        } catch (Exception e) {
            String error = "Failed to join Swarm: " + e.getMessage();
            logger.error("Failed to join Swarm for instance: {}", instance.getId(), e);
            return error;
        }
    }

    private String checkSwarmState(Instance instance) {
        try {
            if (instance.getType().equalsIgnoreCase("local")) {
                String[] command = { "docker", "exec", instance.getProviderId(), "docker", "info", "--format",
                        "{{.Swarm.LocalNodeState}}" };
                Process process = Runtime.getRuntime().exec(command);
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    return reader.readLine();
                }
            } else {
                String command = "docker info --format '{{.Swarm.LocalNodeState}}'";
                // Check if sshKey and secret name are available
                SSHKey sshKey = instance.getSshKey();
                if (sshKey == null || sshKey.getPrivateKeySecretName() == null
                        || sshKey.getPrivateKeySecretName().isEmpty()) {
                    logger.error(
                            "SSH key or private key secret name missing for instance {}. Cannot check swarm state.",
                            instance.getId());
                    return "error";
                }
                return remoteCommandService.executeCommand(
                        instance.getIp().getHostAddress(),
                        sshUser,
                        sshKey.getPrivateKeySecretName(), // Use secret name
                        command,
                        dockerCommandTimeout);
            }
        } catch (Exception e) {
            logger.error("Error checking swarm state for instance {}: {}", instance.getId(), e.getMessage());
            return "error";
        }
    }

    public String leaveSwarm() {
        try {
            dockerClient.leaveSwarmCmd().withForceEnabled(true).exec();
            logger.info("Successfully left Swarm");
            return "Left Swarm successfully";
        } catch (Exception e) {
            logger.error("Failed to leave Swarm", e);
            return null;
        }
    }

    public String listNodes() {
        try {
            return dockerClient.listSwarmNodesCmd().exec().toString();
        } catch (Exception e) {
            logger.error("Failed to list Swarm nodes", e);
            return null;
        }
    }

    public CreateServiceResponse createService(ServiceSpec serviceSpec, Map<String, String> placementConstraints) {
        if (placementConstraints != null && !placementConstraints.isEmpty()) {
            TaskSpec taskSpec = serviceSpec.getTaskTemplate();
            if (taskSpec == null) {
                taskSpec = new TaskSpec();
            }

            ServicePlacement placement = new ServicePlacement();
            List<String> constraints = new ArrayList<>();
            for (Map.Entry<String, String> constraint : placementConstraints.entrySet()) {
                constraints.add(constraint.getKey() + "==" + constraint.getValue());
            }
            placement.withConstraints(constraints);

            taskSpec.withPlacement(placement);
            serviceSpec.withTaskTemplate(taskSpec);
        }

        try {
            return dockerClient.createServiceCmd(serviceSpec).exec();
        } catch (Exception e) {
            logger.error("Failed to create service", e);
            return null;
        }
    }

    public String initializeDockerAndJoinSwarm(Instance instance, SSHKey sshKey) {
        try {
            // First check if this instance is meant to be a swarm manager
            Server server = serverRepository.findByInstance(instance);
            if (server == null) {
                throw new IllegalStateException("No server found for instance: " + instance.getId());
            }

            if (instance.getType().equalsIgnoreCase("local")) {
                // Install Docker in the container
                String installResult = installDockerInContainer(instance, sshKey);
                logger.info("Docker installation result for local instance: {}", installResult);

                // Only need to check if should join - we don't initialize manager instances
                // anymore
                // Instead, the host handles that
                // Instead, the host handles that
                if (Boolean.FALSE.equals(server.getIsSwarmManager())) {
                    // Join existing swarm
                    return joinSwarm(instance, sshKey);
                } else {
                    logger.info("Instance {} is marked as swarm manager but we use host-based swarm management",
                            instance.getId());
                    return "Host is responsible for swarm management";
                }
            } else {
                // For remote instances
                // First install Docker
                String host = instance.getIp().getHostAddress();
                // Use the instance's default user if available, otherwise fall back to
                // configured sshUser
                String user = (instance.getDefaultUser() != null && !instance.getDefaultUser().isEmpty())
                        ? instance.getDefaultUser()
                        : sshUser;

                // Check if sshKey and secret name are available
                if (sshKey == null || sshKey.getPrivateKeySecretName() == null
                        || sshKey.getPrivateKeySecretName().isEmpty()) {
                    logger.error(
                            "SSH key or private key secret name missing for instance {}. Cannot initialize Docker/Swarm.",
                            instance.getId());
                    return "Failed to initialize Docker/Swarm: SSH key secret name missing";
                }
                String privateKeySecretName = sshKey.getPrivateKeySecretName(); // Use secret name

                // Install Docker first
                String installResult = installDocker(host, user, privateKeySecretName); // Pass secret name
                logger.info("Docker installation result for remote instance: {}", installResult);

                // Then join the swarm
                return initializeOrJoinRemoteSwarm(instance, host, user, privateKeySecretName); // Pass secret name
            }
        } catch (Exception e) {
            logger.error("Failed to initialize Docker and join swarm for instance: {}", instance.getId(), e);
            return "Failed to initialize Docker and join swarm: " + e.getMessage();
        }
    }

    private String initializeOrJoinRemoteSwarm(Instance instance, String host, String user, String privateKeySecretName) // Use
                                                                                                                         // secret
                                                                                                                         // name
            throws Exception {
        // Check if the instance is already part of a swarm
        String checkSwarmCommand = "docker info --format '{{.Swarm.LocalNodeState}}'";
        String swarmState = remoteCommandService.executeCommand(host, user, privateKeySecretName, checkSwarmCommand, 10)
                .trim(); // Use secret name

        if ("active".equals(swarmState)) {
            logger.info("Remote instance is already part of a swarm");

            // Check if it's the correct swarm
            boolean inCorrectSwarm = isCorrectSwarm(host, user, privateKeySecretName); // Use secret name
            if (inCorrectSwarm) {
                logger.info("Remote instance is already part of the correct swarm");

                // Get the node ID for database registration
                String getNodeIdCommand = "docker info --format '{{.Swarm.NodeID}}'";
                String nodeId = remoteCommandService
                        .executeCommand(host, user, privateKeySecretName, getNodeIdCommand, 10) // Use secret name
                        .trim();

                if (nodeId != null && !nodeId.isEmpty()) {
                    // Get the server for this instance
                    Server server = serverRepository.findByInstance(instance);
                    if (server != null) {
                        registerNodeIfNotExists(nodeId, server);
                    }
                }

                return "Remote instance is already part of the correct swarm";
            } else {
                // Leave the current swarm first
                String leaveCommand = "docker swarm leave --force";
                remoteCommandService.executeCommand(host, user, privateKeySecretName, leaveCommand, 30); // Use secret
                                                                                                         // name
                logger.info("Forced remote instance to leave incorrect swarm");
            }
        }

        // Find the host server, which should be the swarm manager
        Optional<HostServer> hostServerOpt = hostServerService.findFirst();
        if (hostServerOpt.isEmpty() || hostServerOpt.get().getVpn() == null) {
            throw new IllegalStateException("No host server found or Nebula not configured");
        }

        // Get join token and manager IP
        String joinToken = getWorkerJoinToken();
        String managerNebulaIp = hostServerOpt.get().getVpn().getIp();

        // Verify connectivity to the swarm manager before joining
        boolean hasConnectivity = verifySwarmManagerConnectivity(
                managerNebulaIp, host, user, privateKeySecretName, false, null, 5); // Use secret name

        if (!hasConnectivity) {
            String errorMessage = "Failed to join swarm: Cannot connect to swarm manager at " + managerNebulaIp +
                    " via Nebula network. Ensure Nebula is properly deployed and running.";
            logger.error(errorMessage);
            return errorMessage;
        }

        // Join the swarm
        StringBuilder joinCommand = new StringBuilder();
        joinCommand.append("docker swarm join --token ")
                .append(joinToken)
                .append(" ")
                .append("--advertise-addr ").append(managerNebulaIp) // Add advertise address
                .append(" --listen-addr ").append(managerNebulaIp) // Add listen address
                .append(" ")
                .append(managerNebulaIp)
                .append(":2377");

        String result = remoteCommandService.executeCommand(host, user, privateKeySecretName, joinCommand.toString(),
                30); // Use secret name

        return result;
    }

    private String joinLocalContainerToSwarm(Instance instance, String joinToken, String managerNebulaIp) {
        try {
            // Get the server for this instance to retrieve its Nebula IP
            Server server = serverRepository.findByInstance(instance);
            if (server == null || server.getVpn() == null) {
                throw new IllegalStateException(
                        "Server or Nebula configuration not found for instance: " + instance.getId());
            }

            String containerNebulaIp = server.getVpn().getIp();
            if (containerNebulaIp == null || containerNebulaIp.isEmpty()) {
                throw new IllegalStateException("Container's Nebula IP is not configured");
            }
            // Extract plain IP address from potential CIDR notation
            String plainContainerNebulaIp = containerNebulaIp.split("/")[0].trim();

            String containerId = instance.getProviderId();

            // First check if the container is already part of a swarm
            String[] checkCommand = {
                    "docker", "exec", containerId,
                    "docker", "info", "--format", "{{.Swarm.LocalNodeState}}"
            };

            Process checkProcess = Runtime.getRuntime().exec(checkCommand);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(checkProcess.getInputStream()))) {
                String swarmState = reader.readLine();
                if ("active".equals(swarmState)) {
                    logger.info("Container {} is already part of a swarm", containerId);

                    // Try to determine if it's the correct swarm
                    boolean inCorrectSwarm = isCorrectLocalSwarm(containerId);
                    if (inCorrectSwarm) {
                        logger.info("Container {} is already part of the correct swarm", containerId);

                        // Get the node ID for database registration
                        String[] getNodeIdCommand = {
                                "docker", "exec", containerId,
                                "docker", "info", "--format", "{{.Swarm.NodeID}}"
                        };
                        Process nodeIdProcess = Runtime.getRuntime().exec(getNodeIdCommand);
                        try (BufferedReader nodeIdReader = new BufferedReader(
                                new InputStreamReader(nodeIdProcess.getInputStream()))) {
                            String nodeId = nodeIdReader.readLine();
                            if (nodeId != null && !nodeId.isEmpty()) {
                                registerNodeIfNotExists(nodeId, server);
                            }
                        }

                        return "Container is already part of the correct swarm";
                    } else {
                        logger.info("Container {} is part of a different swarm. Leaving before rejoining...",
                                containerId);

                        // Leave the swarm
                        String[] leaveCommand = {
                                "docker", "exec", containerId,
                                "docker", "swarm", "leave", "--force"
                        };
                        Process leaveProcess = Runtime.getRuntime().exec(leaveCommand);
                        leaveProcess.waitFor();
                    }
                }
            }

            // Verify connectivity to the swarm manager before joining
            boolean hasConnectivity = verifySwarmManagerConnectivity(
                    managerNebulaIp, null, null, null, true, containerId, 5);

            if (!hasConnectivity) {
                String errorMessage = "Failed to join swarm: Cannot connect to swarm manager at " + managerNebulaIp +
                        " via Nebula network. Ensure Nebula is properly deployed and running.";
                logger.error(errorMessage);
                return errorMessage;
            }

            // Join the swarm
            String[] joinCommand = {
                    "docker", "exec", containerId,
                    "docker", "swarm", "join",
                    "--token", joinToken,
                    "--advertise-addr", plainContainerNebulaIp, // Add advertise address
                    "--listen-addr", plainContainerNebulaIp, // Add listen address
                    managerNebulaIp + ":2377"
            };

            StringBuilder output = new StringBuilder();
            Process joinProcess = Runtime.getRuntime().exec(joinCommand);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(joinProcess.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(joinProcess.getErrorStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append("ERROR: ").append(line).append("\n");
                }
            }

            int exitCode = joinProcess.waitFor();
            String result = output.toString();

            if (exitCode != 0) {
                if (result.contains("This node is already part of a swarm")) {
                    logger.info("Container {} is already part of a swarm (from stderr)", containerId);

                    // Check if it's the correct swarm
                    boolean inCorrectSwarm = isCorrectLocalSwarm(containerId);
                    if (inCorrectSwarm) {
                        logger.info("Container {} is already part of the correct swarm", containerId);

                        // Get the node ID for database registration
                        String[] getNodeIdCommand = {
                                "docker", "exec", containerId,
                                "docker", "info", "--format", "{{.Swarm.NodeID}}"
                        };
                        Process nodeIdProcess = Runtime.getRuntime().exec(getNodeIdCommand);
                        try (BufferedReader nodeIdReader = new BufferedReader(
                                new InputStreamReader(nodeIdProcess.getInputStream()))) {
                            String nodeId = nodeIdReader.readLine();
                            if (nodeId != null && !nodeId.isEmpty()) {
                                registerNodeIfNotExists(nodeId, server);
                            }
                        }

                        return "Container is already part of the correct swarm";
                    } else {
                        return "Container is part of a different swarm and failed to leave properly";
                    }
                } else {
                    logger.error("Failed to join container to swarm. Exit code: {}, Output: {}", exitCode, result);
                    return "Failed to join swarm: " + result;
                }
            }

            // Register node ID if join was successful
            if (result.contains("This node joined a swarm as a worker")) {
                logger.info("Container successfully joined the swarm");

                // Get the node ID
                String[] getNodeIdCommand = {
                        "docker", "exec", containerId,
                        "docker", "info", "--format", "{{.Swarm.NodeID}}"
                };
                Process nodeIdProcess = Runtime.getRuntime().exec(getNodeIdCommand);
                try (BufferedReader nodeIdReader = new BufferedReader(
                        new InputStreamReader(nodeIdProcess.getInputStream()))) {
                    String nodeId = nodeIdReader.readLine();
                    if (nodeId != null && !nodeId.isEmpty()) {
                        registerNodeIfNotExists(nodeId, server);
                    }
                }
            }

            return result;
        } catch (Exception e) {
            logger.error("Error joining container to swarm", e);
            return "Failed to join swarm: " + e.getMessage();
        }
    }

    /**
     * Joins a remote instance to the Docker Swarm
     * 
     * @param instance        The instance to join
     * @param sshKey          The SSH key to use for connection
     * @param joinToken       The swarm join token
     * @param managerNebulaIp The Nebula IP of the swarm manager
     * @return Result message
     */
    private String joinRemoteInstanceToSwarm(Instance instance, SSHKey sshKey, String joinToken,
            String managerNebulaIp) {
        try {
            if (instance == null) {
                return "Failed to join swarm: Instance is null";
            }

            // Check if sshKey and secret name are available
            if (sshKey == null || sshKey.getPrivateKeySecretName() == null
                    || sshKey.getPrivateKeySecretName().isEmpty()) {
                logger.error("SSH key or private key secret name missing for instance {}. Cannot join swarm.",
                        instance.getId());
                return "Failed to join swarm: SSH key secret name missing";
            }
            String privateKeySecretName = sshKey.getPrivateKeySecretName(); // Use secret name

            String host = instance.getIp() != null ? instance.getIp().getHostAddress() : null;
            if (host == null || host.isEmpty()) {
                return "Failed to join swarm: Instance IP is not configured";
            }

            // Get the server for this instance to retrieve its Nebula IP
            Server server = serverRepository.findByInstance(instance);
            if (server == null || server.getVpn() == null) {
                logger.warn("Server or Nebula configuration not found for instance: {}", instance.getId());
                // It might still be possible to join if we just advertise the public IP,
                // but it's better to fail if Nebula isn't configured.
                return "Failed to join swarm: Server or Nebula configuration not found for instance "
                        + instance.getId();
            }

            String instanceNebulaIp = server.getVpn().getIp();
            if (instanceNebulaIp == null || instanceNebulaIp.isEmpty()) {
                return "Failed to join swarm: Instance's Nebula IP is not configured";
            }
            // Extract plain IP address from potential CIDR notation
            String plainInstanceNebulaIp = instanceNebulaIp.split("/")[0].trim();

            String user = sshUser;

            // First check if the instance is already part of a swarm
            String checkSwarmCommand = "docker info --format '{{.Swarm.LocalNodeState}}'";
            String swarmState = remoteCommandService
                    .executeCommand(host, user, privateKeySecretName, checkSwarmCommand, 10) // Use secret name
                    .trim();

            if ("active".equals(swarmState)) {
                logger.info("Remote instance is already part of a swarm");

                // Check if it's the correct swarm
                boolean inCorrectSwarm = isCorrectSwarm(host, user, privateKeySecretName); // Use secret name
                if (inCorrectSwarm) {
                    logger.info("Remote instance is already part of the correct swarm");

                    // Get the node ID for database registration
                    String getNodeIdCommand = "docker info --format '{{.Swarm.NodeID}}'";
                    String nodeId = remoteCommandService
                            .executeCommand(host, user, privateKeySecretName, getNodeIdCommand, 10) // Use secret name
                            .trim();

                    if (nodeId != null && !nodeId.isEmpty()) {
                        // Get the server for this instance
                        // Server server = serverRepository.findByInstance(instance); // Remove
                        // duplicate declaration
                        if (server != null) { // Reuse existing server variable
                            registerNodeIfNotExists(nodeId, server);
                        }
                    }

                    return "Remote instance is already part of the correct swarm";
                } else {
                    // Leave the current swarm first
                    String leaveCommand = "docker swarm leave --force";
                    remoteCommandService.executeCommand(host, user, privateKeySecretName, leaveCommand, 30); // Use
                                                                                                             // secret
                                                                                                             // name
                    logger.info("Forced remote instance to leave incorrect swarm");
                }
            }

            // Verify connectivity to the swarm manager before joining
            boolean hasConnectivity = verifySwarmManagerConnectivity(
                    managerNebulaIp, host, user, privateKeySecretName, false, null, 5); // Use secret name

            if (!hasConnectivity) {
                String errorMessage = "Failed to join swarm: Cannot connect to swarm manager at " + managerNebulaIp +
                        " via Nebula network. Ensure Nebula is properly deployed and running.";
                logger.error(errorMessage);
                return errorMessage;
            }

            // Join the swarm
            StringBuilder joinCommand = new StringBuilder();
            joinCommand.append("docker swarm join --token ")
                    .append(joinToken)
                    .append(" ")
                    .append("--advertise-addr ").append(plainInstanceNebulaIp) // Use instance's Nebula IP
                    .append(" --listen-addr ").append(plainInstanceNebulaIp) // Use instance's Nebula IP
                    .append(" ")
                    .append(managerNebulaIp) // Manager's IP for connection
                    .append(":2377");

            String result = remoteCommandService.executeCommand(host, user, privateKeySecretName,
                    joinCommand.toString(), 30); // Use secret name

            // If join was successful, register the node
            if (result.contains("This node joined a swarm as a worker")) {
                // Get the node ID
                String getNodeIdCommand = "docker info --format '{{.Swarm.NodeID}}'";
                String nodeId = remoteCommandService
                        .executeCommand(host, user, privateKeySecretName, getNodeIdCommand, 10) // Use secret name
                        .trim();

                if (nodeId != null && !nodeId.isEmpty()) {
                    // Get the server for this instance
                    // Server server = serverRepository.findByInstance(instance); // Remove
                    // duplicate declaration
                    if (server != null) { // Reuse existing server variable
                        registerNodeIfNotExists(nodeId, server);
                    }
                }
            } else if (result.contains("This node is already part of a swarm")) {
                // Handle the case of already being in the swarm
                boolean inCorrectSwarm = isCorrectSwarm(host, user, privateKeySecretName); // Use secret name
                if (inCorrectSwarm) {
                    logger.info("Remote instance is already part of the correct swarm");

                    // Get the node ID for database registration
                    String getNodeIdCommand = "docker info --format '{{.Swarm.NodeID}}'";
                    String nodeId = remoteCommandService
                            .executeCommand(host, user, privateKeySecretName, getNodeIdCommand, 10) // Use secret name
                            .trim();

                    if (nodeId != null && !nodeId.isEmpty()) {
                        // Get the server for this instance
                        // Server server = serverRepository.findByInstance(instance); // Remove
                        // duplicate declaration
                        if (server != null) { // Reuse existing server variable
                            registerNodeIfNotExists(nodeId, server);
                        }
                    }
                }
            }

            return result;
        } catch (Exception e) {
            logger.error("Failed to join remote instance to swarm", e);
            return "Failed to join swarm: " + e.getMessage();
        }
    }

    /**
     * Checks if a local container is part of the correct swarm
     * 
     * @param containerId The container ID to check
     * @return true if the container is part of the correct swarm, false otherwise
     */
    private boolean isCorrectLocalSwarm(String containerId) {
        try {
            // Get the host (manager) ClusterID
            String[] hostCommand = { "docker", "info" };
            Process hostProcess = Runtime.getRuntime().exec(hostCommand);

            StringBuilder hostOutput = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(hostProcess.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    hostOutput.append(line).append("\n");
                }
            }

            Map<String, String> hostSwarmInfo = parseDockerInfoSwarmData(hostOutput.toString());
            String hostClusterId = hostSwarmInfo.get("ClusterID");

            if (hostClusterId == null) {
                logger.warn("Host ClusterID not found");
                return false;
            }

            // Get the container's ClusterID
            String[] containerCommand = { "docker", "exec", containerId, "docker", "info" };
            Process containerProcess = Runtime.getRuntime().exec(containerCommand);

            StringBuilder containerOutput = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(containerProcess.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    containerOutput.append(line).append("\n");
                }
            }

            Map<String, String> containerSwarmInfo = parseDockerInfoSwarmData(containerOutput.toString());
            String containerClusterId = containerSwarmInfo.get("ClusterID");

            if (containerClusterId == null) {
                logger.warn("Container ClusterID not found");
                return false;
            }

            // Compare ClusterIDs
            boolean isSameCluster = hostClusterId.equals(containerClusterId);
            logger.info("Swarm cluster check - Host ID: {}, Container ID: {}, Same cluster: {}",
                    hostClusterId, containerClusterId, isSameCluster);

            return isSameCluster;
        } catch (Exception e) {
            logger.error("Error checking if container is in the correct swarm", e);
            return false;
        }
    }

    /**
     * Checks if a node is part of the correct swarm by comparing ClusterIDs
     * 
     * @param host       The host to check
     * @param user       The SSH user
     * @param privateKey The SSH private key
     * @return true if the node is part of the correct swarm, false otherwise
     */
    private boolean isCorrectSwarm(String host, String user, String privateKeySecretName) { // Use secret name
        try {
            // Get the host (manager) ClusterID
            String hostDockerInfoCmd = "docker info";
            String hostOutput = executeLocalCommand(hostDockerInfoCmd); // Use existing helper
            Map<String, String> hostSwarmInfo = parseDockerInfoSwarmData(hostOutput);
            String hostClusterId = hostSwarmInfo.get("ClusterID");

            if (hostClusterId == null) {
                logger.warn("Host ClusterID not found");
                return false;
            }

            // Get the remote node's ClusterID
            String remoteDockerInfoCmd = "docker info";
            String remoteOutput = remoteCommandService.executeCommand(host, user, privateKeySecretName,
                    remoteDockerInfoCmd, // Use secret name
                    dockerCommandTimeout);
            Map<String, String> remoteSwarmInfo = parseDockerInfoSwarmData(remoteOutput);
            String remoteClusterId = remoteSwarmInfo.get("ClusterID");

            if (remoteClusterId == null) {
                logger.warn("Remote node ClusterID not found");
                return false;
            }

            // Compare ClusterIDs
            boolean isSameCluster = hostClusterId.equals(remoteClusterId);
            logger.info("Swarm cluster check - Host ID: {}, Remote ID: {}, Same cluster: {}",
                    hostClusterId, remoteClusterId, isSameCluster);

            return isSameCluster;
        } catch (Exception e) {
            logger.error("Error checking if node is in the correct swarm", e);
            return false;
        }
    }

    /**
     * Parse docker info output to extract swarm information
     * 
     * @param dockerInfoOutput The output from docker info command
     * @return Map containing swarm information like NodeID, ClusterID, etc.
     */
    private Map<String, String> parseDockerInfoSwarmData(String dockerInfoOutput) {
        Map<String, String> swarmInfo = new HashMap<>();

        if (dockerInfoOutput == null || dockerInfoOutput.isEmpty()) {
            return swarmInfo;
        }

        // Extract key swarm information
        String[] lines = dockerInfoOutput.split("\\n");
        boolean inSwarmSection = false;

        for (String line : lines) {
            line = line.trim();

            if (line.equals("Swarm:")) {
                inSwarmSection = true;
                continue;
            }

            if (inSwarmSection) {
                if (line.isEmpty() || !line.contains(":")) {
                    // End of swarm section or invalid line
                    inSwarmSection = false;
                    continue;
                }

                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    String key = parts[0].trim();
                    String value = parts[1].trim();
                    swarmInfo.put(key, value);
                }
            }

            // Directly capture these important fields regardless of section
            if (line.startsWith("NodeID:")) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    swarmInfo.put("NodeID", parts[1].trim());
                }
            } else if (line.startsWith("ClusterID:")) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    swarmInfo.put("ClusterID", parts[1].trim());
                }
            }
        }

        return swarmInfo;
    }

    /**
     * Registers a node in the database if it doesn't already exist
     * 
     * @param nodeId The Docker Swarm node ID
     * @param server The server associated with this node
     */
    private void registerNodeIfNotExists(String nodeId, Server server) {
        try {
            // Check if node already exists in database
            Optional<SwarmNode> existingNode = swarmNodeRepository.findByNodeId(nodeId);
            if (existingNode.isPresent()) {
                logger.info("Node already exists in database with ID: {}", existingNode.get().getId());
                return;
            }

            // Determine if this is a manager or worker node
            String role = server.getIsSwarmManager() ? "manager" : "worker";

            // Create and save new node
            SwarmNode newNode = new SwarmNode();
            newNode.setNodeId(nodeId);
            newNode.setHostname(server.getDetails() != null ? server.getDetails().getName() : "unknown");
            newNode.setRole(role);
            newNode.setStatus("ready");
            newNode.setServer(server);

            SwarmNode savedNode = swarmNodeRepository.save(newNode);
            logger.info("Registered new swarm node in database with ID: {}", savedNode.getId());

            // Apply labels for the node
            applyNodeLabels(nodeId, server);
        } catch (Exception e) {
            logger.error("Failed to register node in database", e);
        }
    }

    /**
     * Registers a host server as a node in the database if it doesn't already exist
     * 
     * @param nodeId     The Docker Swarm node ID
     * @param hostServer The host server associated with this node
     */
    public void registerNodeIfNotExists(String nodeId, HostServer hostServer) {
        try {
            // Check if node already exists in database
            Optional<SwarmNode> existingNode = swarmNodeRepository.findByNodeId(nodeId);
            if (existingNode.isPresent()) {
                logger.info("Host node already exists in database with ID: {}", existingNode.get().getId());
                return;
            }

            // For host servers, they are always managers
            String role = "manager";

            // Create and save new node
            SwarmNode newNode = new SwarmNode();
            newNode.setNodeId(nodeId);
            newNode.setHostname(hostServer.getHostname());
            newNode.setRole(role);
            newNode.setStatus("ready");

            // Note: For host servers, we can't set the server field as it's a different
            // type
            // But this is okay for visualization purposes

            SwarmNode savedNode = swarmNodeRepository.save(newNode);
            logger.info("Registered host server as swarm node in database with ID: {}", savedNode.getId());

            // Apply labels for the node
            applyNodeLabels(nodeId, hostServer);
        } catch (Exception e) {
            logger.error("Failed to register host server as node in database", e);
        }
    }

    /**
     * Checks if Docker Swarm is already initialized on the host machine.
     * Uses a consistent shell execution approach for reliability.
     * 
     * @return true if swarm is already initialized, false otherwise
     */
    private boolean isSwarmAlreadyInitializedOnHost() {
        try {
            logger.info("Checking if Docker Swarm is already initialized on host");

            // Use a shell to properly execute the command
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "docker info --format '{{.Swarm.LocalNodeState}}'");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            int exitCode = process.waitFor();
            String result = output.toString().trim();

            logger.info("Docker Swarm state check result: '{}', exit code: {}", result, exitCode);

            boolean isActive = result != null && result.trim().equalsIgnoreCase("active");
            if (isActive) {
                logger.info("Docker Swarm is already active on host");
            } else {
                logger.info("Docker Swarm is not active on host (state: {})", result);
            }

            return isActive;
        } catch (Exception e) {
            logger.error("Failed to check if swarm is initialized on host", e);
            return false;
        }
    }

    /**
     * Executes a command locally on the host machine.
     * 
     * @param command The command to execute
     * @return The command output
     * @throws IOException If an I/O error occurs
     */
    private String executeLocalCommand(String command) throws IOException {
        logger.info("Executing local command: {}", command);
        Process process = Runtime.getRuntime().exec(command);

        StringBuilder output = new StringBuilder();
        try (BufferedReader stdout = new BufferedReader(new InputStreamReader(process.getInputStream()));
                BufferedReader stderr = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {

            String line;
            while ((line = stdout.readLine()) != null) {
                output.append(line).append("\n");
                logger.info("STDOUT: {}", line);
            }
            while ((line = stderr.readLine()) != null) {
                output.append("ERROR: ").append(line).append("\n");
                logger.error("STDERR: {}", line);
            }
        }

        try {
            int exitCode = process.waitFor();
            logger.info("Command '{}' exited with code {}", command, exitCode);

            if (exitCode != 0 && !command.contains("|| true")) {
                throw new RuntimeException(
                        "Command failed with exit code: " + exitCode + ", output: " + output.toString());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Command execution interrupted", e);
        }

        return output.toString();
    }

    private String executeCommand(String[] command) throws Exception {
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();

        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
            logger.info("Process output: {}", line);
        }

        int exitCode = process.waitFor();
        logger.info("Process exit code: {}", exitCode);

        if (exitCode == 0) {
            logger.info("Command executed successfully. Output: {}", output.toString());
            return output.toString();
        } else {
            logger.error("Command execution failed. Exit code: {}. Output: {}", exitCode, output.toString());
            return "Command execution failed: " + output.toString();
        }
    }

    /**
     * Gets the worker join token for Docker Swarm.
     * Enhanced to initialize the swarm if needed and use a more reliable approach.
     * Since the swarm manager is now the host machine, this method
     * executes the command directly on the host.
     * Includes retry logic for better reliability.
     * 
     * @return The worker join token
     * @throws IOException If getting the token fails after all retries
     */
    private String getWorkerJoinToken() throws IOException {
        boolean swarmInitialized = isSwarmAlreadyInitializedOnHost();

        if (!swarmInitialized) {
            // We should never get here if joinExistingSwarm is working correctly,
            // but just in case, initialize the swarm
            logger.warn("Swarm not initialized yet when trying to get worker token. Initializing first...");

            try {
                // Find host server
                Optional<HostServer> hostServerOpt = hostServerService.findFirst();
                if (hostServerOpt.isEmpty() || hostServerOpt.get().getVpn() == null) {
                    throw new IOException("No host server found or Nebula not configured");
                }

                HostServer hostServer = hostServerOpt.get();
                String nebulaIp = hostServer.getVpn().getIp();
                if (nebulaIp == null || nebulaIp.isEmpty()) {
                    throw new IOException("Host's Nebula IP not configured");
                }

                // Extract plain IP from CIDR notation if present
                String plainIp = nebulaIp.split("/")[0].trim();

                // Initialize swarm
                String initCommand = String.format(
                        "docker swarm init --advertise-addr %s:2377 --listen-addr %s:2377",
                        plainIp, plainIp);

                logger.info("Initializing swarm with command: {}", initCommand);

                ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", initCommand);
                pb.redirectErrorStream(true);
                Process process = pb.start();

                StringBuilder output = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\n");
                        logger.info("INIT STDOUT: {}", line);
                    }
                }

                int exitCode = process.waitFor();
                String result = output.toString();

                if (exitCode != 0 &&
                        !result.contains("this node is already part of a swarm") &&
                        !result.contains("already part of a swarm")) {
                    throw new IOException("Failed to initialize swarm: " + result);
                }

                // Mark host as swarm manager
                hostServer.setSwarmManager(true);
                hostServerService.save(hostServer);

                // Register the host as a swarm node in the database using central method
                registerHostSwarmNode(hostServer);

                // Give Docker a moment to fully initialize
                Thread.sleep(2000);

                // Now the swarm should be initialized
                swarmInitialized = true;
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while initializing swarm", ie);
            } catch (IOException ioe) {
                throw ioe;
            } catch (Exception e) {
                throw new IOException("Failed to initialize swarm: " + e.getMessage(), e);
            }
        }

        for (int attempt = 1; attempt <= 3; attempt++) {
            try {
                logger.info("Getting worker join token (attempt {}/{})", attempt, 3);

                // Use a more reliable approach with ProcessBuilder
                ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "docker swarm join-token -q worker");
                pb.redirectErrorStream(true);
                Process process = pb.start();

                StringBuilder output = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\n");
                    }
                }

                int exitCode = process.waitFor();
                String result = output.toString().trim();

                // Check for success
                if (exitCode == 0 && result.length() > 20) {
                    logger.info("Successfully retrieved worker join token");
                    return result;
                } else {
                    logger.warn("Retrieved token appears invalid (too short or error): {}", result);
                }
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while getting join token", ie);
            } catch (Exception e) {
                logger.warn("Failed to get worker join token on attempt {}: {}", attempt, e.getMessage());

                if (attempt < 3) {
                    try {
                        int delaySeconds = 3 * attempt;
                        logger.info("Waiting {} seconds before retry...", delaySeconds);
                        Thread.sleep(delaySeconds * 1000);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted while waiting to retry getting join token", ie);
                    }
                }
            }
        }

        throw new IOException("Failed to get worker join token after 3 attempts");
    }

    // Custom exceptions
    public static class SwarmJoinException extends RuntimeException {
        public SwarmJoinException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class DockerInstallationException extends RuntimeException {
        public DockerInstallationException(String message) {
            super(message);
        }

        public DockerInstallationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Installs Docker in a container (instance)
     * 
     * @param instance The instance where Docker should be installed
     * @param sshKey   The SSH key to use for connection
     * @return Result message
     * @throws Exception If installation fails
     */
    public String installDockerInContainer(Instance instance, SSHKey sshKey) throws Exception {
        // Check if sshKey and secret name are available
        if (sshKey == null || sshKey.getPrivateKeySecretName() == null || sshKey.getPrivateKeySecretName().isEmpty()) {
            logger.error("SSH key or private key secret name missing for instance {}. Cannot install Docker.",
                    instance.getId());
            return "Failed to install Docker: SSH key secret name missing";
        }
        String privateKeySecretName = sshKey.getPrivateKeySecretName(); // Use secret name

        String host = instance.getIp().getHostAddress();
        String user = "root"; // or the appropriate user for your container

        logger.info("Starting Docker installation in container: {}", instance.getId());

        // Use the same installDocker method
        return installDocker(host, user, privateKeySecretName); // Use secret name
    }

    /**
     * Installs Docker on a remote machine
     * 
     * @param host       The host address
     * @param user       The SSH user
     * @param privateKey The SSH private key
     * @return Result message
     * @throws Exception If installation fails
     */
    private String installDocker(String host, String user, String privateKeySecretName) throws Exception { // Use secret
                                                                                                           // name
        logger.info("Starting Docker installation on host: {}", host);

        // Check if Docker is already installed
        String checkDockerCommand = "docker --version";
        try {
            String dockerVersion = remoteCommandService.executeCommand(host, user, privateKeySecretName,
                    checkDockerCommand, 10); // Use secret name
            if (dockerVersion != null && dockerVersion.contains("Docker version")) {
                logger.info("Docker is already installed: {}", dockerVersion.trim());
                return "Docker is already installed";
            }
        } catch (Exception e) {
            logger.info("Docker is not installed. Proceeding with installation.");
        }

        // Check for curl availability
        String checkCurlCommand = "which curl";
        boolean hasCurl = false;
        try {
            String curlPath = remoteCommandService.executeCommand(host, user, privateKeySecretName, checkCurlCommand,
                    10); // Use secret name
            hasCurl = curlPath != null && !curlPath.isEmpty();
        } catch (Exception e) {
            logger.info("Curl is not available. Will use wget.");
        }

        String installCommand;
        if (hasCurl) {
            installCommand = "curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh";
            logger.info("Using curl to install Docker");
        } else {
            installCommand = "wget -qO- https://get.docker.com | sh";
            logger.info("Using wget to install Docker");
        }

        try {
            String result = remoteCommandService.executeCommand(host, user, privateKeySecretName, installCommand, // Use
                                                                                                                  // secret
                                                                                                                  // name
                    dockerInstallTimeout);
            logger.info("Docker installation result: {}", result);

            // Verify installation
            String verifyCommand = "docker --version";
            String verificationResult = remoteCommandService.executeCommand(host, user, privateKeySecretName,
                    verifyCommand, 10); // Use secret name
            if (verificationResult != null && verificationResult.contains("Docker version")) {
                logger.info("Docker installed successfully: {}", verificationResult.trim());
                return "Docker installation successful";
            } else {
                logger.error("Docker installation verification failed. Result: {}", verificationResult);
                return "Docker installation failed";
            }
        } catch (Exception e) {
            logger.error("Error during Docker installation", e);
            return "Docker installation failed: " + e.getMessage();
        }
    }

    /**
     * Applies a Docker configuration to an instance
     * 
     * @param instance     The instance to apply the configuration to
     * @param dockerConfig The Docker configuration to apply
     * @return Result message
     */
    public String applyDockerConfig(Instance instance, DockerConfig dockerConfig) {
        logger.info("Applying Docker config '{}' to instance {}", dockerConfig.getName(), instance.getId());

        if (instance == null || dockerConfig == null) {
            throw new IllegalArgumentException("Instance and Docker config must not be null");
        }

        try {
            // First, check if the instance is part of the swarm
            String swarmStatus = checkSwarmState(instance);
            if (!"active".equalsIgnoreCase(swarmStatus)) {
                logger.warn("Instance {} is not active in the swarm. Current status: {}",
                        instance.getId(), swarmStatus);
                return "Error: Instance not active in swarm";
            }

            // Get the host and SSH credentials for the instance
            String host = instance.getIp().getHostAddress(); // Get host address as string
            String user = sshUser;
            SSHKey sshKey = instance.getSshKey();

            // Check if sshKey and secret name are available
            if (sshKey == null || sshKey.getPrivateKeySecretName() == null
                    || sshKey.getPrivateKeySecretName().isEmpty()) {
                logger.error("SSH key or private key secret name missing for instance {}. Cannot apply Docker config.",
                        instance.getId());
                return "Error: SSH key secret name missing";
            }
            String privateKeySecretName = sshKey.getPrivateKeySecretName(); // Use secret name

            // Parse Docker config content
            String configContent = dockerConfig.getContent();

            // Create a temporary file with the config content on the remote instance
            String remoteTempPath = "/tmp/docker_config_" + dockerConfig.getId() + ".yml";
            // Ensure proper escaping for the echo command
            String createFileCmd = "echo '" + configContent.replace("'", "'\\''") + "' > " + remoteTempPath;

            // Using correct method signature with timeout parameter
            String createFileResult = remoteCommandService.executeCommand(
                    host, user, privateKeySecretName, createFileCmd, dockerCommandTimeout); // Use secret name
            logger.debug("Created config file on instance {}: {}", instance.getId(), createFileResult);

            // Apply the configuration
            String applyCmd = "docker stack deploy -c " + remoteTempPath + " " + dockerConfig.getName();
            String result = remoteCommandService.executeCommand(
                    host, user, privateKeySecretName, applyCmd, dockerCommandTimeout); // Use secret name

            // Clean up the temporary file
            String cleanupCmd = "rm " + remoteTempPath;
            remoteCommandService.executeCommand(
                    host, user, privateKeySecretName, cleanupCmd, dockerCommandTimeout); // Use secret name

            logger.info("Successfully applied Docker config '{}' to instance {}",
                    dockerConfig.getName(), instance.getId());

            return result;
        } catch (Exception e) {
            logger.error("Failed to apply Docker config to instance {}", instance.getId(), e);
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Event handler for ApplyDockerConfigEvent
     * 
     * @param event The event to handle
     */
    @EventListener
    public void handleApplyDockerConfigEvent(ApplyDockerConfigEvent event) {
        Server server = event.getServer();
        DockerConfig dockerConfig = server.getDockerConfig();
        Instance instance = server.getInstance();

        if (instance == null || dockerConfig == null) {
            logger.warn("Missing instance or Docker config for server {}", server.getId());
            return;
        }

        try {
            String result = applyDockerConfig(instance, dockerConfig);
            logger.info("Docker config applied to server {}: {}", server.getId(), result);
        } catch (Exception e) {
            logger.error("Failed to apply Docker config to server {}", server.getId(), e);
        }
    }

    /**
     * Verifies connectivity to the swarm manager via Nebula network
     * 
     * @param managerNebulaIp The Nebula IP of the swarm manager
     * @param host            The host to execute commands on (can be null for local
     *                        execution)
     * @param user            The SSH user (can be null for local execution)
     * @param privateKey      The SSH private key (can be null for local execution)
     * @param isLocal         Whether this is a local container check
     * @param containerId     The container ID (required if isLocal is true)
     * @param maxAttempts     Maximum number of ping attempts
     * @return true if connectivity is established, false otherwise
     */
    private boolean verifySwarmManagerConnectivity(String managerNebulaIp, String host, String user, String privateKey,
            boolean isLocal, String containerId, int maxAttempts) {

        // Ensure network tools are installed before attempting connectivity checks
        try {
            ensureNetworkToolsInstalled(host, user, privateKey, isLocal, containerId);
        } catch (Exception e) {
            logger.warn("Failed to ensure network tools are installed: {}. Connectivity checks might fail.",
                    e.getMessage());
            // Continue anyway, maybe tools are already there or installation failure was
            // temporary
        }

        logger.info("Verifying connectivity to swarm manager at {}", managerNebulaIp);

        // Extract plain IP from CIDR notation if present
        String plainIp = managerNebulaIp.split("/")[0].trim();

        // Prepare ping command
        String pingCmd = String.format("ping -c 1 -W 2 %s", plainIp);

        // Also try to verify Docker Swarm port is accessible
        String portCheckCmd = String.format("nc -z -v -w 2 %s 2377 || echo 'PORT_CHECK_FAILED'", plainIp);

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                String pingResult;
                String portResult;

                if (isLocal) {
                    // Execute in local container
                    String[] pingCommand = {
                            "docker", "exec", containerId, "/bin/sh", "-c", pingCmd
                    };
                    Process pingProcess = Runtime.getRuntime().exec(pingCommand);
                    int pingExitCode = pingProcess.waitFor();

                    pingResult = pingExitCode == 0 ? "SUCCESS" : "FAILED";

                    // Check port
                    String[] portCommand = {
                            "docker", "exec", containerId, "/bin/sh", "-c", portCheckCmd
                    };
                    Process portProcess = Runtime.getRuntime().exec(portCommand);

                    try (BufferedReader reader = new BufferedReader(
                            new InputStreamReader(portProcess.getInputStream()))) {
                        portResult = reader.lines().collect(Collectors.joining("\n"));
                    }
                } else {
                    // Execute on remote host
                    pingResult = remoteCommandService.executeCommand(host, user, privateKey,
                            pingCmd + " || echo 'PING_FAILED'", 10);
                    portResult = remoteCommandService.executeCommand(host, user, privateKey, portCheckCmd, 10);
                }

                boolean pingSuccess = !pingResult.contains("FAILED");
                boolean portSuccess = !portResult.contains("FAILED") && !portResult.contains("refused");

                if (pingSuccess) {
                    logger.info("Successfully pinged swarm manager at {} (attempt {}/{})", plainIp, attempt,
                            maxAttempts);

                    if (portSuccess) {
                        logger.info("Successfully verified swarm port connectivity at {}:2377", plainIp);
                        return true;
                    } else {
                        logger.warn("Can ping swarm manager but port 2377 is not accessible. Will retry...");
                    }
                } else {
                    logger.warn("Failed to ping swarm manager at {} (attempt {}/{})", plainIp, attempt, maxAttempts);
                }
            } catch (Exception e) {
                logger.warn("Error checking connectivity to swarm manager (attempt {}/{}): {}",
                        attempt, maxAttempts, e.getMessage());
            }

            if (attempt < maxAttempts) {
                try {
                    // Increase wait time with each attempt
                    int waitTime = attempt * 2; // 2s, 4s, 6s, etc.
                    logger.info("Waiting {} seconds before next connectivity check attempt...", waitTime);
                    Thread.sleep(waitTime * 1000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    logger.warn("Interrupted while waiting between connectivity check attempts");
                }
            }
        }

        logger.error("Failed to establish connectivity to swarm manager after {} attempts", maxAttempts);
        return false;
    }

    /**
     * Ensures ping and netcat tools are installed on the target.
     * Installs them using apt-get if they are missing.
     * 
     * @param host        Target host IP (null if local)
     * @param user        SSH user (null if local)
     * @param privateKey  SSH key (null if local)
     * @param isLocal     True if target is a local container
     * @param containerId Container ID (required if isLocal is true)
     * @throws Exception If command execution fails unexpectedly
     */
    private void ensureNetworkToolsInstalled(String host, String user, String privateKey, boolean isLocal,
            String containerId) throws Exception {
        logger.info("Checking for required network tools (ping, nc) on target: {}", isLocal ? containerId : host);

        // Commands to check if tools are installed
        String checkPingCmd = "which ping || echo 'PING_MISSING'";
        String checkNcCmd = "which nc || echo 'NC_MISSING'";
        boolean pingMissing = false;
        boolean ncMissing = false;

        try {
            if (isLocal) {
                // Check in container
                String[] pingCheckCommand = {
                        "docker", "exec", containerId, "/bin/sh", "-c", checkPingCmd
                };
                Process pingCheckProcess = Runtime.getRuntime().exec(pingCheckCommand);
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(pingCheckProcess.getInputStream()))) {
                    String result = reader.lines().collect(Collectors.joining("\n"));
                    pingMissing = result.contains("PING_MISSING");
                }

                String[] ncCheckCommand = {
                        "docker", "exec", containerId, "/bin/sh", "-c", checkNcCmd
                };
                Process ncCheckProcess = Runtime.getRuntime().exec(ncCheckCommand);
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(ncCheckProcess.getInputStream()))) {
                    String result = reader.lines().collect(Collectors.joining("\n"));
                    ncMissing = result.contains("NC_MISSING");
                }
            } else {
                // Check on remote host
                String pingCheckResult = remoteCommandService.executeCommand(host, user, privateKey, checkPingCmd, 10);
                pingMissing = pingCheckResult.contains("PING_MISSING");

                String ncCheckResult = remoteCommandService.executeCommand(host, user, privateKey, checkNcCmd, 10);
                ncMissing = ncCheckResult.contains("NC_MISSING");
            }

            logger.info("Network tools check - ping missing: {}, nc missing: {}", pingMissing, ncMissing);

            if (pingMissing || ncMissing) {
                logger.info("Installing missing network tools on {}", isLocal ? containerId : host);

                // Command to install the missing tools
                StringBuilder installCmd = new StringBuilder("apt-get update && apt-get install -y");
                if (pingMissing) {
                    installCmd.append(" iputils-ping");
                }
                if (ncMissing) {
                    installCmd.append(" netcat");
                }

                if (isLocal) {
                    String[] installCommand = {
                            "docker", "exec", containerId, "/bin/sh", "-c", installCmd.toString()
                    };
                    Process installProcess = Runtime.getRuntime().exec(installCommand);
                    int exitCode = installProcess.waitFor();
                    logger.info("Network tools installation in container {} completed with exit code: {}",
                            containerId, exitCode);

                    if (exitCode != 0) {
                        try (BufferedReader reader = new BufferedReader(
                                new InputStreamReader(installProcess.getErrorStream()))) {
                            String errorOutput = reader.lines().collect(Collectors.joining("\n"));
                            logger.warn("Installation error output: {}", errorOutput);
                        }
                    }
                } else {
                    // Install on remote host with increased timeout
                    String result = remoteCommandService.executeCommand(host, user, privateKey, installCmd.toString(),
                            180);
                    logger.info("Network tools installation result: {}", result);
                }
            } else {
                logger.info("All required network tools are already installed");
            }
        } catch (Exception e) {
            logger.error("Error during network tools installation", e);
            throw e;
        }
    }

    /**
     * Registers the host machine as a node in the swarm.
     * This is a central method that should be called whenever the host is
     * initialized as a swarm manager.
     * 
     * @param hostServer The host server to register
     * @return true if registration was successful, false otherwise
     */
    public boolean registerHostSwarmNode(HostServer hostServer) {
        try {
            String nodeId = getLocalNodeId();
            if (nodeId != null && !nodeId.isEmpty()) {
                registerNodeIfNotExists(nodeId, hostServer);
                logger.info("Successfully registered host swarm manager node with ID: {}", nodeId);
                return true;
            } else {
                logger.warn("Could not determine host node ID for registration");
                return false;
            }
        } catch (Exception e) {
            logger.error("Failed to register host swarm manager node", e);
            return false;
        }
    }

    @EventListener
    public void handleSwarmManagerInitializedEvent(SwarmManagerInitializedEvent event) {
        logger.info("Handling SwarmManagerInitializedEvent for host server");

        if (event.isHostSwarmManager()) {
            HostServer hostServer = event.getHostServer();
            registerHostSwarmNode(hostServer);
        }
    }

    /**
     * Gets the Docker node ID of the local node
     * 
     * @return The node ID or null if it couldn't be determined
     */
    private String getLocalNodeId() {
        try {
            String output = executeLocalCommand("docker info --format '{{.Swarm.NodeID}}'");
            if (output != null && !output.trim().isEmpty() && !output.contains("null")) {
                return output.trim().replace("'", "");
            }

            // Try the alternate approach using node ls
            output = executeLocalCommand("docker node ls -q --filter 'role=manager'");
            if (output != null && !output.trim().isEmpty()) {
                // Get the first line as the manager node ID
                return output.trim().split("\n")[0].trim();
            }

            return null;
        } catch (Exception e) {
            logger.error("Error getting local node ID", e);
            return null;
        }
    }

    /**
     * Event listener that automatically joins a server to the Docker Swarm
     * when Nebula is successfully deployed.
     * 
     * @param event The NebulaDeployedEvent
     */
    @EventListener
    public void handleNebulaDeployed(NebulaDeployedEvent event) {
        logger.info("Handling NebulaDeployedEvent for server ID: {}", event.getServerId());

        try {
            // Skip if this is a host server deployment
            if (event.getSource() instanceof NebulaDeploymentService &&
                    event.getSource().toString().contains("deployNebulaToHost")) {
                logger.info("Skipping swarm join for host server deployment");
                return;
            }

            // Skip if this is a lighthouse Nebula deployment
            Long nebulaConfigId = event.getNebulaConfigId();
            if (nebulaConfigId != null) {
                // *** Add logging to verify nebulaConfigId ***
                logger.info("Attempting to fetch Nebula config with ID: {}", nebulaConfigId);
                Nebula nebulaConfig = nebulaService.getNebulaConfigById(nebulaConfigId);
                if (nebulaConfig != null && nebulaConfig.getLighthouse()) {
                    logger.info("Skipping swarm join for lighthouse Nebula deployment");
                    return;
                }
            }

            // Find the server by ID - convert UUID to Long safely
            try {
                // Extract the server ID from the deterministic UUID
                // For our deterministic UUIDs, the server ID is stored in the least significant
                // bits
                Long serverId = event.getServerId().getLeastSignificantBits();
                logger.info("Looking up server with ID: {}", serverId);

                Optional<Server> serverOpt = serverRepository.findById(serverId);
                if (serverOpt.isEmpty()) {
                    logger.warn("Cannot find server with ID: {} for swarm join", event.getServerId());
                    return;
                }

                Server server = serverOpt.get();
                logger.info("Found server: {}, class: {}", server.getId(), server.getClass().getSimpleName());

                Instance instance = server.getInstance();

                if (instance == null) {
                    logger.warn("Server {} has no instance associated", server.getId());
                    return;
                }

                logger.info("Found instance: {}, type: {}", instance.getId(), instance.getType());

                // Skip local instances - no Docker-in-Docker
                if (instance.getType().equalsIgnoreCase("local")) {
                    logger.info("Skipping swarm join for local instance: {}", instance.getId());
                    return;
                }

                // Get SSH key from the instance
                SSHKey sshKey = instance.getSshKey();
                if (sshKey == null) {
                    logger.warn("No SSH key found for instance: {}", instance.getId());
                    return;
                }

                logger.info("Found SSH key, proceeding with swarm join for server: {}", server.getId());

                // Join the server to the swarm
                logger.info("Joining server {} to Docker Swarm after Nebula deployment", server.getId());
                CompletableFuture.runAsync(() -> {
                    try {
                        // Wait a moment to ensure Nebula is fully up and running
                        logger.info("Waiting 5 seconds for Nebula to stabilize before joining swarm...");
                        Thread.sleep(5000);

                        logger.info("Executing joinSwarm for instance: {}", instance.getId());
                        String result = joinSwarm(instance, sshKey);

                        if (result.contains("Error") || result.contains("Failed")) {
                            logger.error("Failed to join server {} to swarm: {}", server.getId(), result);
                        } else {
                            logger.info("Successfully joined server {} to swarm: {}", server.getId(), result);
                        }
                    } catch (Exception e) {
                        logger.error("Error joining server {} to swarm", server.getId(), e);
                    }
                }, executorService);
            } catch (NumberFormatException e) {
                logger.error("Invalid server ID format: {}", event.getServerId(), e);
            }
        } catch (Exception e) {
            logger.error("Error handling NebulaDeployedEvent", e);
        }
    }

    /**
     * Apply standard labels to a node in the swarm
     * 
     * @param nodeId The Docker Swarm node ID
     * @param server The server associated with the node
     */
    private void applyNodeLabels(String nodeId, Server server) {
        try {
            if (server == null)
                return;

            // Apply standard labels for identifying the node
            executeLocalCommand("docker node update --label-add server_id=" + server.getId() + " " + nodeId);

            // Apply server type label
            String serverType = server.getClass().getSimpleName();
            executeLocalCommand("docker node update --label-add server_type=" + serverType + " " + nodeId);

            logger.info("Applied labels to node {}: server_id={}, server_type={}",
                    nodeId, server.getId(), serverType);
        } catch (Exception e) {
            logger.error("Failed to apply labels to node " + nodeId, e);
        }
    }

    /**
     * Apply standard labels to a host node in the swarm
     * 
     * @param nodeId     The Docker Swarm node ID
     * @param hostServer The host server associated with the node
     */
    public void applyNodeLabels(String nodeId, HostServer hostServer) {
        try {
            if (hostServer == null)
                return;

            // Apply standard labels for identifying the node
            executeLocalCommand("docker node update --label-add hostname=" + hostServer.getHostname() + " " + nodeId);
            executeLocalCommand("docker node update --label-add server_id=" + hostServer.getId() + " " + nodeId);
            executeLocalCommand("docker node update --label-add server_type=HostServer " + nodeId);

            logger.info("Applied labels to host node {}: hostname={}, server_id={}",
                    nodeId, hostServer.getHostname(), hostServer.getId());
        } catch (Exception e) {
            logger.error("Failed to apply labels to host node " + nodeId, e);
        }
    }
}