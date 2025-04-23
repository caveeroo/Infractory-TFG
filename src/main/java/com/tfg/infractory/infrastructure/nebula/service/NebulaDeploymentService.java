package com.tfg.infractory.infrastructure.nebula.service;

import java.util.*;
import java.io.*;
import java.nio.file.*;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.core.io.ResourceLoader;
import org.springframework.context.event.EventListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.context.ApplicationEventPublisher;
import com.tfg.infractory.domain.model.*;
import com.tfg.infractory.web.event.*;
import com.tfg.infractory.infrastructure.ssh.model.SSHKey;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;
import com.tfg.infractory.domain.repository.*;
import com.tfg.infractory.infrastructure.secrets.model.Secret;
import com.tfg.infractory.infrastructure.secrets.service.SecretsService;
import com.tfg.infractory.infrastructure.ssh.service.RemoteCommandService;
import com.tfg.infractory.infrastructure.docker.service.DockerSwarmService;
import com.tfg.infractory.domain.service.InstanceService;
import com.tfg.infractory.domain.service.HostServerService;
import org.springframework.core.io.Resource;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class NebulaDeploymentService {

    private static final Logger logger = LoggerFactory.getLogger(NebulaDeploymentService.class);

    private static final String CONFIG_DIRECTORY = "/etc/nebula";
    // private static final String NEBULA_CERT_PATH =
    // "classpath:nebula/nebula-cert";
    private static final String NEBULA_BINARY_PATH = "classpath:nebula/nebula";

    private final ExecutorService executorService;
    private final InstanceRepository instanceRepository;
    private final NebulaCertificateService nebulaCertificateService;
    private final SecretsService secretsService;
    private final RemoteCommandService remoteCommandService;
    private final ServerRepository serverRepository;
    private final ResourceLoader resourceLoader;
    private final NebulaRepository nebulaRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final HostServerService hostServerService;

    // Create a map to store locks for each client name to prevent multiple threads
    // from generating certificates for the same client simultaneously
    private static final ConcurrentHashMap<String, Object> nameLocks = new ConcurrentHashMap<>();

    // Add a class-level lock object for host deployment synchronization
    private static final Object HOST_DEPLOYMENT_LOCK = new Object();

    // Add a flag to track if host deployment is in progress
    private static final AtomicBoolean HOST_DEPLOYMENT_IN_PROGRESS = new AtomicBoolean(false);

    private static final ConcurrentHashMap<Long, AtomicBoolean> serverDeploymentFlags = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Long, Object> serverLocks = new ConcurrentHashMap<>();

    @Autowired
    public NebulaDeploymentService(InstanceRepository instanceRepository,
            NebulaCertificateService nebulaCertificateService,
            SecretsService secretsService,
            RemoteCommandService remoteCommandService,
            ServerRepository serverRepository,
            ResourceLoader resourceLoader,
            NebulaRepository nebulaRepository,
            DockerSwarmService dockerSwarmService,
            ApplicationEventPublisher eventPublisher,
            InstanceService instanceService,
            HostServerService hostServerService) {
        this.instanceRepository = instanceRepository;
        this.nebulaCertificateService = nebulaCertificateService;
        this.secretsService = secretsService;
        this.remoteCommandService = remoteCommandService;
        this.serverRepository = serverRepository;
        this.resourceLoader = resourceLoader;
        this.nebulaRepository = nebulaRepository;
        this.eventPublisher = eventPublisher;
        this.hostServerService = hostServerService;
        this.executorService = Executors.newCachedThreadPool();
    }

    // Main deployment methods
    @Transactional
    public CompletableFuture<Void> deployNebulaToInstance(Long serverId, Long nebulaConfigId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                DeploymentContext context = prepareDeployment(serverId, nebulaConfigId);

                // Check if this is a lighthouse and ensure it's not a local instance
                if (context.nebulaConfig().getLighthouse() &&
                        "Local".equals(context.instance().getProvider().getName())) {
                    throw new IllegalStateException("Lighthouse cannot be deployed on a local instance");
                }

                deployNebula(context.instance(), context.sshKey(), context.nebulaConfigContent());
                logger.info("Nebula deployed successfully to server: {}", serverId);

                if (context.nebulaConfig().getLighthouse()) {
                    eventPublisher.publishEvent(new LighthouseNebulaDeployedEvent(this, context.nebulaConfig()));
                    logger.info("Published LighthouseNebulaDeployedEvent for Nebula ID: {}",
                            context.nebulaConfig().getId());
                } else {
                    // For non-lighthouse servers, publish a general deployment event to trigger
                    // Docker Swarm join
                    // Convert numeric ID to a deterministic UUID to avoid format errors
                    UUID serverUuid = new UUID(0, serverId);
                    // *** Use the original nebulaConfigId passed to the method ***
                    eventPublisher
                            .publishEvent(new NebulaDeployedEvent(this, serverUuid, nebulaConfigId));
                    logger.info(
                            "Published NebulaDeployedEvent for server {} with config ID {} to trigger Docker Swarm join",
                            serverId, nebulaConfigId); // Log the ID being published
                }

                return null;
            } catch (Exception e) {
                logger.error("Failed to deploy Nebula to server: {}. Error: {}", serverId, e.getMessage(), e);
                throw new DeploymentException("Failed to deploy Nebula to server: " + serverId, e);
            }
        }, executorService);
    }

    @Transactional
    public CompletableFuture<Void> deployNebulaToLocalInstance(Long serverId, Long nebulaConfigId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                DeploymentContext context = prepareDeployment(serverId, nebulaConfigId);
                deployNebulaToLocalContainer(context.instance(), context.nebulaConfig(), context.nebulaConfigContent());
                logger.info("Nebula deployed successfully to local server: {}", serverId);
                return null;
            } catch (Exception e) {
                logger.error("Failed to deploy Nebula to local server: {}. Error: {}", serverId, e.getMessage(), e);
                throw new DeploymentException("Failed to deploy Nebula to local server: " + serverId, e);
            }
        }, executorService);
    }

    public CompletableFuture<Void> deployNebulaToAllInstances(Nebula nebulaConfig) {
        List<Instance> instances = instanceRepository.findAll();
        List<CompletableFuture<Void>> futures = instances.stream()
                .map(instance -> deployNebulaToInstance(instance.getId(), nebulaConfig.getId()))
                .collect(Collectors.toList());

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .thenRun(() -> logger.info("Nebula deployed to all instances successfully"))
                .exceptionally(e -> {
                    logger.error("Error deploying Nebula to one or more instances", e);
                    throw new CompletionException("Failed to deploy Nebula to all instances", e);
                });
    }

    // Deployment preparation
    private DeploymentContext prepareDeployment(Long serverId, Long nebulaConfigId) throws Exception {
        Server server = getServerById(serverId);
        Instance instance = getInstanceFromServer(server);
        Nebula nebulaConfig = getNebulaConfigById(nebulaConfigId);

        ensureDefaultLighthouseIp(nebulaConfig);
        SSHKey sshKey = getSSHKeyFromInstance(instance);
        Map<String, String> lighthouseIpMap = getLighthouseIpMap(nebulaConfig);
        String nebulaConfigContent = generateNebulaConfig(nebulaConfig, instance, lighthouseIpMap);
        List<String> allowedRoles = getAllowedRoles(nebulaConfig);

        // Ensure CA exists before generating client certificates
        ensureCAExists();

        // Use the retry mechanism for generating client certificates
        generateClientCertWithRetry(instance, nebulaConfig, allowedRoles);

        return new DeploymentContext(server, instance, nebulaConfig, nebulaConfigContent, allowedRoles, sshKey);
    }

    // Entity retrieval methods
    private Server getServerById(Long serverId) {
        return serverRepository.findById(serverId)
                .orElseThrow(() -> new EntityNotFoundException("Server not found"));
    }

    private Instance getInstanceFromServer(Server server) {
        // Return null instead of throwing an exception when the server doesn't have an
        // instance
        // This allows the deployNebula method to handle the case when the instance is
        // null
        return server.getInstance();
    }

    private Nebula getNebulaConfigById(Long nebulaConfigId) {
        return nebulaRepository.findByIdWithAllCollections(nebulaConfigId)
                .orElseThrow(() -> new EntityNotFoundException("Nebula configuration not found"));
    }

    private SSHKey getSSHKeyFromInstance(Instance instance) {
        // Return null if the instance is null or if it doesn't have an SSH key
        if (instance == null) {
            return null;
        }
        return instance.getSshKey();
    }

    // Lighthouse IP management
    private void ensureDefaultLighthouseIp(Nebula nebulaConfig) {
        if (!nebulaConfig.getLighthouse()
                && (nebulaConfig.getLighthouseIps() == null || nebulaConfig.getLighthouseIps().isEmpty())) {
            String defaultLighthouseIp = generateDefaultLighthouseIp(nebulaConfig.getIp(), nebulaConfig.getSubnet());
            nebulaConfig.setLighthouseIps(Collections.singleton(defaultLighthouseIp));
            nebulaRepository.save(nebulaConfig);
            logger.info("Created default lighthouse with IP: {} for Nebula config: {}", defaultLighthouseIp,
                    nebulaConfig.getId());
        }
    }

    private String generateDefaultLighthouseIp(String nebulaIp, int subnet) {
        try {
            InetAddress inetAddress = InetAddress.getByName(nebulaIp);
            byte[] bytes = inetAddress.getAddress();
            int ipInt = ByteBuffer.wrap(bytes).getInt();

            int maskBits = 32 - subnet;
            int mask = 0xFFFFFFFF << maskBits;
            int network = ipInt & mask;
            int broadcast = network | ~mask;

            int usableIps = broadcast - network - 1;
            int middleOffset = usableIps / 2;

            int generatedIp = network + middleOffset;
            if (generatedIp == ipInt) {
                generatedIp++;
            }

            byte[] generatedBytes = ByteBuffer.allocate(4).putInt(generatedIp).array();
            InetAddress generatedAddress = InetAddress.getByAddress(generatedBytes);

            return generatedAddress.getHostAddress();
        } catch (Exception e) {
            logger.error("Error generating default Lighthouse IP for: {}/{}", nebulaIp, subnet, e);
            throw new RuntimeException("Error generating default Lighthouse IP", e);
        }
    }

    private Map<String, String> getLighthouseIpMap(Nebula nebulaConfig) {
        if (nebulaConfig.getLighthouse()) {
            return Collections.emptyMap();
        }

        return serverRepository.findAll().stream()
                .filter(server -> server.getVpn() != null && server.getVpn().getLighthouse()
                        && server.getInstance() != null && server.getInstance().getIp() != null)
                .collect(Collectors.toMap(
                        server -> server.getVpn().getIp(),
                        server -> server.getInstance().getIp().getHostAddress()));
    }

    // Certificate management
    private void ensureCAExists() {
        // Use double-checked locking pattern for thread safety
        Optional<Secret> caKey = secretsService.getSecretByName("nebula_ca_key");
        Optional<Secret> caCert = secretsService.getSecretByName("nebula_ca_cert");

        if (caKey.isEmpty() || caCert.isEmpty()) {
            // Synchronize on a class-level lock to ensure only one thread generates the CA
            synchronized (NebulaDeploymentService.class) {
                // Check again inside the synchronized block
                caKey = secretsService.getSecretByName("nebula_ca_key");
                caCert = secretsService.getSecretByName("nebula_ca_cert");

                if (caKey.isEmpty() || caCert.isEmpty()) {
                    logger.info("CA key or cert not found. Generating new CA (synchronized)...");
                    try {
                        nebulaCertificateService.generateAndSaveCA();
                        logger.info("CA generated successfully");

                        // Verify that the CA was created
                        caKey = secretsService.getSecretByName("nebula_ca_key");
                        caCert = secretsService.getSecretByName("nebula_ca_cert");

                        if (caKey.isEmpty() || caCert.isEmpty()) {
                            throw new RuntimeException("Failed to generate CA certificates");
                        }
                    } catch (Exception e) {
                        logger.error("Failed to generate CA certificates", e);
                        throw new RuntimeException("Failed to generate CA certificates", e);
                    }
                } else {
                    logger.info("Existing CA found inside synchronized block. Using the existing CA for Nebula VPN.");
                }
            }
        } else {
            logger.info("Existing CA found. Using the existing CA for Nebula VPN.");
        }
    }

    /**
     * Generates a Nebula client certificate for an instance with retry mechanism.
     * Uses per-client locking to avoid race conditions.
     *
     * @param instance     The instance to generate a certificate for
     * @param nebulaConfig The Nebula configuration
     * @param allowedRoles The roles allowed for this certificate
     */
    private void generateClientCertWithRetry(Instance instance, Nebula nebulaConfig, List<String> allowedRoles) {
        final int MAX_RETRIES = 3;
        String name;
        // Host does not have an instance, as its the host server
        if (instance == null) {
            name = "host";
        } else {
            name = instance.getName();
        }

        // Get a unique lock for this client name to ensure thread safety
        Object lock = getNameLock(name);

        // Synchronize on the client-specific lock
        synchronized (lock) {
            logger.info("Generating Nebula client certificate for {} (attempt 1/{}, synchronized)", name, MAX_RETRIES);

            // Check if client certificate already exists to avoid duplication
            Optional<Secret> clientKey = secretsService.getSecretByName("nebula_" + name + "_key");
            Optional<Secret> clientCert = secretsService.getSecretByName("nebula_" + name + "_cert");

            if (clientKey.isPresent() && clientCert.isPresent()) {
                logger.info("Client certificate for {} already exists. Skipping generation.", name);
                return;
            } else if (clientKey.isPresent() || clientCert.isPresent()) {
                // If only one exists, delete both to ensure consistent state
                logger.warn("Found incomplete certificate set for {}. Deleting and regenerating.", name);
                if (clientKey.isPresent()) {
                    secretsService.deleteSecretByName("nebula_" + name + "_key");
                }
                if (clientCert.isPresent()) {
                    secretsService.deleteSecretByName("nebula_" + name + "_cert");
                }
            }

            try {
                // Generate the client certificate - convert List to Set
                String ipWithSubnet = nebulaConfig.getIp() + "/" + nebulaConfig.getSubnet();
                Set<String> groups = new HashSet<>(allowedRoles);

                logger.info("Generating certificate with IP {} and groups {}", ipWithSubnet, groups);
                nebulaCertificateService.generateAndSaveClientCert(name, ipWithSubnet, groups);

                // Verify the certificate was actually generated
                clientKey = secretsService.getSecretByName("nebula_" + name + "_key");
                clientCert = secretsService.getSecretByName("nebula_" + name + "_cert");

                if (!clientKey.isPresent() || !clientCert.isPresent()) {
                    throw new RuntimeException("Failed to generate certificate - secrets not found after generation");
                }

                logger.info("Successfully generated Nebula client certificate for {}", name);
            } catch (Exception e) {
                logger.error("Error generating Nebula client certificate for {} on attempt 1: {}", name,
                        e.getMessage());
                // Retry logic
                for (int attempt = 2; attempt <= MAX_RETRIES; attempt++) {
                    try {
                        logger.info("Retrying generation of Nebula client certificate for {} (attempt {}/{})", name,
                                attempt, MAX_RETRIES);
                        String ipWithSubnet = nebulaConfig.getIp() + "/" + nebulaConfig.getSubnet();
                        Set<String> groups = new HashSet<>(allowedRoles);
                        nebulaCertificateService.generateAndSaveClientCert(name, ipWithSubnet, groups);

                        // Verify the certificate was actually generated
                        clientKey = secretsService.getSecretByName("nebula_" + name + "_key");
                        clientCert = secretsService.getSecretByName("nebula_" + name + "_cert");

                        if (!clientKey.isPresent() || !clientCert.isPresent()) {
                            throw new RuntimeException(
                                    "Failed to generate certificate - secrets not found after generation");
                        }

                        logger.info("Successfully generated Nebula client certificate for {} on attempt {}", name,
                                attempt);
                        return;
                    } catch (Exception retryEx) {
                        logger.error("Error generating Nebula client certificate for {} on attempt {}: {}", name,
                                attempt, retryEx.getMessage());
                        if (attempt == MAX_RETRIES) {
                            throw new RuntimeException(
                                    "Failed to generate Nebula client certificate after " + MAX_RETRIES + " attempts",
                                    retryEx);
                        }
                        try {
                            Thread.sleep(1000 * attempt); // Exponential backoff
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        }
                    }
                }
                throw new RuntimeException("Failed to generate Nebula client certificate", e);
            }
        }
    }

    // Get or create a lock object for the given name
    private Object getNameLock(String name) {
        return nameLocks.computeIfAbsent(name, k -> new Object());
    }

    private List<String> getAllowedRoles(Nebula nebulaConfig) {
        return nebulaConfig.getAllowedRoles() != null ? new ArrayList<>(nebulaConfig.getAllowedRoles())
                : new ArrayList<>();
    }

    // Nebula configuration generation
    private String generateNebulaConfig(Nebula nebulaConfig, Instance instance, Map<String, String> lighthouseIpMap) {
        StringBuilder config = new StringBuilder();

        appendPkiConfig(config, instance);
        appendStaticHostMap(config, lighthouseIpMap);
        appendLighthouseConfig(config, nebulaConfig);
        appendListenConfig(config);
        appendPunchyConfig(config);
        appendTunConfig(config);
        appendLoggingConfig(config);
        appendFirewallConfig(config, nebulaConfig, instance);

        String generatedConfig = config.toString();
        logger.info("Generated Nebula config: \n{}", generatedConfig);

        return generatedConfig;
    }

    private void appendPkiConfig(StringBuilder config, Instance instance) {
        config.append("pki:\n")
                .append("  ca: /etc/nebula/ca.crt\n");

        // Use "host" as the name for host machine certificates when instance is null
        // For host-based deployments, always use "host" as the name
        String name = (instance != null && !"host".equals(instance.getType())) ? instance.getName() : "host";
        config.append("  cert: /etc/nebula/").append(name).append(".crt\n")
                .append("  key: /etc/nebula/").append(name).append(".key\n");
    }

    private void appendStaticHostMap(StringBuilder config, Map<String, String> lighthouseIpMap) {
        config.append("static_host_map:\n");
        for (Map.Entry<String, String> entry : lighthouseIpMap.entrySet()) {
            config.append("  \"").append(entry.getKey()).append("\": [\"").append(entry.getValue())
                    .append(":4242\"]\n");
        }
    }

    private void appendLighthouseConfig(StringBuilder config, Nebula nebulaConfig) {
        config.append("lighthouse:\n");
        if (nebulaConfig.getLighthouse()) {
            config.append("  am_lighthouse: ").append(nebulaConfig.getLighthouse()).append("\n")
                    .append("  interval: 20\n");
        } else {
            config.append("  hosts:\n");
            for (String lighthouseIp : nebulaConfig.getLighthouseIps()) {
                config.append("    - \"").append(lighthouseIp).append("\"\n");
            }
        }
    }

    private void appendListenConfig(StringBuilder config) {
        config.append("listen:\n")
                .append("  host: 0.0.0.0\n")
                .append("  port: 4242\n");
    }

    private void appendPunchyConfig(StringBuilder config) {
        config.append("punchy:\n")
                .append("  punch: true\n");
    }

    private void appendTunConfig(StringBuilder config) {
        config.append("tun:\n")
                .append("  disabled: false\n")
                .append("  dev: nebula1\n")
                .append("  drop_local_broadcast: false\n")
                .append("  drop_multicast: false\n")
                .append("  tx_queue: 500\n")
                .append("  mtu: 1300\n");
    }

    private void appendLoggingConfig(StringBuilder config) {
        config.append("logging:\n")
                .append("  level: info\n")
                .append("  format: text\n");
    }

    private void appendFirewallConfig(StringBuilder config, Nebula nebulaConfig, Instance instance) {
        config.append("firewall:\n")
                .append("  outbound:\n")
                .append("    - port: any\n")
                .append("      proto: any\n")
                .append("      host: any\n");

        config.append("  inbound:\n");
        if (nebulaConfig.getAllowedCIDRs() != null) {
            for (String cidr : nebulaConfig.getAllowedCIDRs()) {
                config.append("    - port: any\n")
                        .append("      proto: any\n")
                        .append("      cidr: ").append(cidr).append("\n");
            }
        }
        if (nebulaConfig.getAllowedRoles() != null) {
            for (String role : nebulaConfig.getAllowedRoles()) {
                config.append("    - port: any\n")
                        .append("      proto: any\n")
                        .append("      groups:\n")
                        .append("        - ").append(role).append("\n");
            }
        }

        // Add Docker Swarm specific rules based on instance name or if it's the host
        if (instance != null && "docker-swarm-manager".equals(instance.getName())) {
            appendSwarmManagerFirewallRules(config);
        } else if (instance == null) {
            // If instance is null, this is the host, which is a swarm manager
            appendSwarmManagerFirewallRules(config);
        } else {
            appendWorkerFirewallRules(config);
        }
    }

    private void appendSwarmManagerFirewallRules(StringBuilder config) {
        config.append("    - port: 2377\n")
                .append("      proto: tcp\n")
                .append("      host: any\n")
                .append("    - port: 7946\n")
                .append("      proto: any\n")
                .append("      host: any\n")
                .append("    - port: 4789\n")
                .append("      proto: udp\n")
                .append("      host: any\n");
    }

    private void appendWorkerFirewallRules(StringBuilder config) {
        config.append("    - port: 7946\n")
                .append("      proto: any\n")
                .append("      host: any\n")
                .append("    - port: 4789\n")
                .append("      proto: udp\n")
                .append("      host: any\n");
    }

    // Remote deployment methods
    private void deployNebula(Instance instance, SSHKey sshKey, String nebulaConfigContent) throws Exception {
        // Check if this is a host deployment (instance is null)
        if (instance == null || instance.getIp() == null) {
            logger.info("Detected host deployment - using local deployment approach");
            // For host deployment, we'll use local commands instead of SSH
            boolean isRoot = isRunningAsRoot();

            // Create config directory and set permissions (no change needed here)
            String mkdirCommand = isRoot ? "mkdir -p " + CONFIG_DIRECTORY + " || true"
                    : "sudo mkdir -p " + CONFIG_DIRECTORY + " || true";
            String chmodDirCommand = isRoot ? "chmod 755 " + CONFIG_DIRECTORY + " || true"
                    : "sudo chmod 755 " + CONFIG_DIRECTORY + " || true";

            executeLocalCommand(mkdirCommand);
            executeLocalCommand(chmodDirCommand);

            // Write config file directly using tee, no temporary file
            String configPath = CONFIG_DIRECTORY + "/config.yml";
            String[] teeConfigCmd = isRoot ? new String[] { "tee", configPath }
                    : new String[] { "sudo", "tee", configPath };
            logger.info("Writing Nebula config to {} using {}", configPath, (isRoot ? "tee" : "sudo tee"));
            executeLocalCommandWithInput(teeConfigCmd, nebulaConfigContent.getBytes(), "Write Nebula config");

            // Set config file permissions
            String chmodConfigCommand = isRoot ? "chmod 644 " + configPath
                    : "sudo chmod 644 " + configPath;
            executeLocalCommand(chmodConfigCommand);
            logger.info("Set permissions for {}", configPath);

            // Upload certificates (this method will be refactored next)
            uploadLocalCertificates(isRoot, nebulaConfigContent);

            // Upload Nebula executable (no change needed here)
            uploadLocalNebulaExecutable(isRoot);

            // Start Nebula process (no change needed here)
            startLocalNebulaProcess(isRoot);

            return; // Host deployment finished
        }

        // Regular remote deployment via SSH
        String host = instance.getIp().getHostAddress();
        String user = "root";
        // Get the secret name instead of the raw key
        String privateKeySecretName = sshKey.getPrivateKeySecretName();
        if (privateKeySecretName == null || privateKeySecretName.isEmpty()) {
            throw new RuntimeException("SSH key secret name is missing for instance: " + instance.getId());
        }

        createConfigDirectory(host, user, privateKeySecretName);
        uploadNebulaConfig(host, user, privateKeySecretName, nebulaConfigContent);
        // uploadClientCertAndKey already gets the instance, which has the SSHKey
        uploadClientCertAndKey(host, user, privateKeySecretName, instance);
        uploadCACert(host, user, privateKeySecretName);
        uploadNebulaExecutable(host, user, privateKeySecretName);
        startNebulaProcess(host, user, privateKeySecretName);
    }

    // Helper methods for local deployment
    private void uploadLocalCertificates(boolean isRoot, String configContent) throws Exception {
        // Upload CA certificate
        Optional<Secret> caCertSecret = secretsService.getSecretByName("nebula_ca_cert");
        if (caCertSecret.isEmpty()) {
            throw new RuntimeException("CA certificate not found");
        }
        byte[] caContent = caCertSecret.get().getContent().getBytes();
        String caPath = CONFIG_DIRECTORY + "/ca.crt";

        // Write CA cert directly using tee
        String[] teeCaCmd = isRoot ? new String[] { "tee", caPath }
                : new String[] { "sudo", "tee", caPath };
        logger.info("Writing CA certificate to {} using {}", caPath, (isRoot ? "tee" : "sudo tee"));
        executeLocalCommandWithInput(teeCaCmd, caContent, "Write CA cert");

        // Set CA cert permissions
        String chmodCaCommand = isRoot ? "chmod 644 " + caPath
                : "sudo chmod 644 " + caPath;
        executeLocalCommand(chmodCaCommand);
        logger.info("Set permissions for {}", caPath);

        // Extract the certificate name from the configuration to ensure they match
        String certName = extractCertNameFromConfig(configContent);
        if (certName == null) {
            certName = "host"; // Default to host if we can't extract the name
            logger.warn("Failed to extract certificate name from configuration, using default: host");
        }

        logger.info("Using certificate name from configuration: {}", certName);

        // Upload client certificate and key - use the actual certificate name from the
        // configuration
        Optional<Secret> clientCertSecret = secretsService.getSecretByName("nebula_" + certName + "_cert");
        Optional<Secret> clientKeySecret = secretsService.getSecretByName("nebula_" + certName + "_key");

        if (clientCertSecret.isEmpty() || clientKeySecret.isEmpty()) {
            logger.error("Client certificates not found with names 'nebula_{}_cert/key', tried looking for name: {}",
                    certName, certName);

            // Try with "host" as a fallback
            if (!certName.equals("host")) {
                logger.info("Trying fallback to host certificates");
                clientCertSecret = secretsService.getSecretByName("nebula_host_cert");
                clientKeySecret = secretsService.getSecretByName("nebula_host_key");

                if (clientCertSecret.isEmpty() || clientKeySecret.isEmpty()) {
                    logger.error("Fallback host certificates not found either");
                    throw new RuntimeException("Client certificates not found");
                } else {
                    // We found host certificates, but we need to update the config
                    logger.warn(
                            "Found host certificates but config uses a different name. The configuration may need to be updated.");
                    // Update certName to reflect the fallback certificates being used
                    certName = "host";
                }
            } else {
                throw new RuntimeException("Client certificates not found");
            }
        }

        byte[] clientCertContent = clientCertSecret.get().getContent().getBytes();
        byte[] clientKeyContent = clientKeySecret.get().getContent().getBytes();

        String certPath = CONFIG_DIRECTORY + "/" + certName + ".crt";
        String keyPath = CONFIG_DIRECTORY + "/" + certName + ".key";

        // Write client cert directly using tee
        String[] teeCertCmd = isRoot ? new String[] { "tee", certPath }
                : new String[] { "sudo", "tee", certPath };
        logger.info("Writing client certificate to {} using {}", certPath, (isRoot ? "tee" : "sudo tee"));
        executeLocalCommandWithInput(teeCertCmd, clientCertContent, "Write client cert " + certName);

        // Write client key directly using tee
        String[] teeKeyCmd = isRoot ? new String[] { "tee", keyPath }
                : new String[] { "sudo", "tee", keyPath };
        logger.info("Writing client key to {} using {}", keyPath, (isRoot ? "tee" : "sudo tee"));
        executeLocalCommandWithInput(teeKeyCmd, clientKeyContent, "Write client key " + certName);

        // Set permissions for client cert and key
        String chmodCertCommand = isRoot ? "chmod 644 " + certPath
                : "sudo chmod 644 " + certPath;
        String chmodKeyCommand = isRoot ? "chmod 600 " + keyPath
                : "sudo chmod 600 " + keyPath;

        executeLocalCommand(chmodCertCommand);
        executeLocalCommand(chmodKeyCommand);
        logger.info("Set permissions for client cert ({}) and key ({})", certPath, keyPath);
    }

    // Helper method to extract certificate name from configuration
    private String extractCertNameFromConfig(String configContent) {
        try {
            // Use simple pattern matching to extract the cert name from the config
            Pattern pattern = Pattern.compile("cert:\\s*/etc/nebula/([^.]+)\\.crt", Pattern.MULTILINE);
            Matcher matcher = pattern.matcher(configContent);
            if (matcher.find()) {
                return matcher.group(1);
            }
        } catch (Exception e) {
            logger.warn("Error extracting certificate name from config: {}", e.getMessage());
        }
        return null;
    }

    private void uploadLocalNebulaExecutable(boolean isRoot) throws Exception {
        InputStream nebulaBinaryStream = null;
        String resourcePath = "/nebula/nebula"; // Standard path for getResourceAsStream

        try {
            // Try standard Java resource loading first
            nebulaBinaryStream = getClass().getResourceAsStream(resourcePath);

            if (nebulaBinaryStream == null) {
                // Fallback to Spring's ResourceLoader if standard way fails
                logger.warn("Standard resource loading failed for {}, trying ResourceLoader with path: {}",
                        resourcePath, NEBULA_BINARY_PATH);
                Resource nebulaResource = resourceLoader.getResource(NEBULA_BINARY_PATH);
                if (!nebulaResource.exists()) {
                    logger.error("ResourceLoader also failed to find resource at {}. Resource: {}", NEBULA_BINARY_PATH,
                            nebulaResource);
                    throw new RuntimeException(
                            "Nebula binary not found in resources using both standard loading and ResourceLoader.");
                }
                nebulaBinaryStream = nebulaResource.getInputStream();
                logger.info("Successfully loaded resource using ResourceLoader fallback.");
            } else {
                logger.info("Successfully loaded resource using standard getClass().getResourceAsStream().");
            }

            if (nebulaBinaryStream == null) {
                // This should theoretically not be reachable if the above logic is sound
                throw new RuntimeException("Failed to obtain InputStream for Nebula binary.");
            }

            // Stop any running Nebula processes before replacing the executable
            logger.info("Stopping any running Nebula processes before replacing the executable...");
            try {
                String[] killCommands = {
                        // Kill by process name
                        isRoot ? "pkill -9 nebula || true" : "sudo pkill -9 nebula || true",
                        // Alternative for killing nebula processes
                        isRoot ? "killall -9 nebula || true" : "sudo killall -9 nebula || true"
                };

                for (String cmd : killCommands) {
                    executeLocalCommand(cmd);
                }

                // Small delay to ensure process is fully terminated
                Thread.sleep(1000);
            } catch (Exception e) {
                logger.warn("Error stopping Nebula processes: {}", e.getMessage());
                // Continue anyway as we still want to try updating the binary
            }

            String tempFile = "/tmp/nebula_" + System.currentTimeMillis();
            try (InputStream is = nebulaBinaryStream) { // Use the obtained stream
                Files.copy(is, Paths.get(tempFile), StandardCopyOption.REPLACE_EXISTING);
            } finally {
                // Ensure the initial stream is closed if it wasn't the one used in
                // try-with-resources
                if (nebulaBinaryStream != null) {
                    try {
                        nebulaBinaryStream.close();
                    } catch (IOException ioe) {
                        /* ignore */ }
                }
            }

            String cpBinaryCommand = isRoot ? "cp " + tempFile + " /usr/local/bin/nebula"
                    : "sudo cp " + tempFile + " /usr/local/bin/nebula";
            String chmodBinaryCommand = isRoot ? "chmod 755 /usr/local/bin/nebula"
                    : "sudo chmod 755 /usr/local/bin/nebula";

            executeLocalCommand(cpBinaryCommand);
            executeLocalCommand(chmodBinaryCommand);

            Files.delete(Paths.get(tempFile));

        } catch (IOException e) {
            logger.error("IOException during Nebula binary handling", e);
            throw new RuntimeException("IOException handling Nebula binary", e);
        }
        // Removed redundant finally block closing the stream again
    }

    private void startLocalNebulaProcess(boolean isRoot) throws Exception {
        String startCommand = isRoot
                ? "nohup /usr/local/bin/nebula -config " + CONFIG_DIRECTORY + "/config.yml > /var/log/nebula.log 2>&1 &"
                : "sudo nohup /usr/local/bin/nebula -config " + CONFIG_DIRECTORY
                        + "/config.yml > /var/log/nebula.log 2>&1 &";

        executeLocalCommand(startCommand);

        // Wait for Nebula to start
        Thread.sleep(2000);
    }

    // Signature updated: privateKey -> privateKeySecretName
    private void createConfigDirectory(String host, String user, String privateKeySecretName) throws Exception {
        String mkdirCommand = "mkdir -p " + CONFIG_DIRECTORY;
        remoteCommandService.executeCommand(host, user, privateKeySecretName, mkdirCommand, 10);
    }

    // Signature updated: privateKey -> privateKeySecretName
    private void uploadNebulaConfig(String host, String user, String privateKeySecretName, String nebulaConfigContent)
            throws Exception {
        // Pass content directly as bytes, no temporary file needed
        remoteCommandService.uploadFile(host, user, privateKeySecretName, CONFIG_DIRECTORY + "/config.yml",
                nebulaConfigContent.getBytes());
        // Ensure correct permissions
        remoteCommandService.executeCommand(host, user, privateKeySecretName,
                "chmod 644 " + CONFIG_DIRECTORY + "/config.yml", 10);
        logger.info("Uploaded Nebula config to {} for host {}", CONFIG_DIRECTORY + "/config.yml", host);
    }

    // Signature updated: privateKey -> privateKeySecretName
    private void uploadClientCertAndKey(String host, String user, String privateKeySecretName, Instance instance)
            throws Exception {
        // Determine the correct certificate name (instance name or 'host')
        String name = (instance != null && !"host".equals(instance.getType())) ? instance.getName() : "host";
        logger.info("Uploading client cert/key for name: {} to host: {}", name, host);

        // Fetch secrets
        Optional<Secret> clientCertSecret = secretsService.getSecretByName("nebula_" + name + "_cert");
        Optional<Secret> clientKeySecret = secretsService.getSecretByName("nebula_" + name + "_key");

        // Check if secrets exist, potentially trying 'host' as fallback if applicable
        if (clientCertSecret.isEmpty() || clientKeySecret.isEmpty()) {
            logger.error("Client certificates not found with names 'nebula_{}_cert/key'", name);
            if (instance != null && !"host".equals(name)) { // Only try fallback if instance is not null and name is not
                                                            // already 'host'
                logger.info("Trying fallback to 'host' certificates for instance {}", instance.getId());
                clientCertSecret = secretsService.getSecretByName("nebula_host_cert");
                clientKeySecret = secretsService.getSecretByName("nebula_host_key");

                if (clientCertSecret.isEmpty() || clientKeySecret.isEmpty()) {
                    logger.error("Fallback 'host' certificates also not found.");
                    throw new RuntimeException(
                            "Client certificates not found for instance: " + name + " (including fallback)");
                } else {
                    logger.warn(
                            "Using fallback 'host' certificates for instance {}. Ensure Nebula config reflects 'host' cert/key paths.",
                            instance.getId());
                    name = "host"; // Update name to 'host' as we are using these certs
                }
            } else {
                throw new RuntimeException("Client certificates not found for name: " + name);
            }
        }

        // Get content as bytes
        byte[] certContent = clientCertSecret.get().getContent().getBytes();
        byte[] keyContent = clientKeySecret.get().getContent().getBytes();

        // Define remote paths using the determined name
        String remoteCertPath = CONFIG_DIRECTORY + "/" + name + ".crt";
        String remoteKeyPath = CONFIG_DIRECTORY + "/" + name + ".key";

        // Upload content directly as bytes
        remoteCommandService.uploadFile(host, user, privateKeySecretName, remoteCertPath, certContent);
        remoteCommandService.uploadFile(host, user, privateKeySecretName, remoteKeyPath, keyContent);
        logger.info("Uploaded client cert and key for name '{}' to host {}", name, host);

        // Set permissions
        remoteCommandService.executeCommand(host, user, privateKeySecretName, "chmod 644 " + remoteCertPath, 10);
        remoteCommandService.executeCommand(host, user, privateKeySecretName, "chmod 600 " + remoteKeyPath, 10);
        logger.info("Set permissions for client cert and key on host {}", host);
    }

    // Signature updated: privateKey -> privateKeySecretName
    private void uploadCACert(String host, String user, String privateKeySecretName) throws Exception {
        Optional<Secret> caCertSecret = secretsService.getSecretByName("nebula_ca_cert");
        if (caCertSecret.isEmpty()) {
            throw new EntityNotFoundException("Nebula CA certificate not found");
        }
        // Get content as bytes
        byte[] caCertContent = caCertSecret.get().getContent().getBytes();
        String remotePath = CONFIG_DIRECTORY + "/ca.crt";

        // Upload content directly as bytes
        remoteCommandService.uploadFile(host, user, privateKeySecretName, remotePath, caCertContent);
        logger.info("Uploaded CA cert to {} for host {}", remotePath, host);

        // Set permissions
        remoteCommandService.executeCommand(host, user, privateKeySecretName, "chmod 644 " + remotePath, 10);
        logger.info("Set permissions for CA cert on host {}", host);
    }

    // Signature updated: privateKey -> privateKeySecretName
    private void uploadNebulaExecutable(String host, String user, String privateKeySecretName) throws Exception {
        try (InputStream nebulaBinaryStream = resourceLoader.getResource(NEBULA_BINARY_PATH).getInputStream()) {
            byte[] nebulaBinaryContent = nebulaBinaryStream.readAllBytes();
            remoteCommandService.uploadFile(host, user, privateKeySecretName, "/usr/local/bin/nebula",
                    nebulaBinaryContent);
            remoteCommandService.executeCommand(host, user, privateKeySecretName, "chmod +x /usr/local/bin/nebula", 10);
            logger.info("Nebula binary uploaded and set as executable for instance: {}", host);
        } catch (IOException e) {
            logger.error("Failed to upload Nebula binary for instance: {}", host, e);
            throw new RuntimeException("Failed to upload Nebula binary", e);
        }
    }

    // Signature updated: privateKey -> privateKeySecretName
    private void startNebulaProcess(String host, String user, String privateKeySecretName) throws Exception {
        String startCommand = "nohup /usr/local/bin/nebula -config " + CONFIG_DIRECTORY
                + "/config.yml > /var/log/nebula.log 2>&1 &";
        remoteCommandService.executeCommand(host, user, privateKeySecretName, startCommand, 10);
        logger.info("Nebula process started on instance: {}", host);
    }

    // Local container deployment methods
    private void deployNebulaToLocalContainer(Instance instance, Nebula nebulaConfig, String nebulaConfigContent)
            throws Exception {
        String containerId = instance.getProviderId();

        createNebulaDirectoryInContainer(containerId);
        uploadNebulaConfigToContainer(containerId, nebulaConfigContent);
        uploadNebulaClientCertAndKeyToContainer(instance, containerId);
        uploadNebulaCACertToContainer(containerId);
        uploadNebulaExecutableToContainer(containerId);
        startNebulaProcessInContainer(containerId);

        logger.info("Nebula process started on local instance: {}", instance.getId());
    }

    private void createNebulaDirectoryInContainer(String containerId) throws Exception {
        String mkdirCommand = "docker exec " + containerId + " mkdir -p " + CONFIG_DIRECTORY;
        executeLocalCommand(mkdirCommand);
    }

    private void uploadNebulaConfigToContainer(String containerId, String nebulaConfigContent) throws Exception {
        uploadFileToLocalContainer(containerId, CONFIG_DIRECTORY + "/config.yml", nebulaConfigContent);
    }

    private void uploadNebulaClientCertAndKeyToContainer(Instance instance, String containerId) throws Exception {
        String name = instance.getName();
        Optional<Secret> clientCert = secretsService.getSecretByName("nebula_" + name + "_cert");
        Optional<Secret> clientKey = secretsService.getSecretByName("nebula_" + name + "_key");

        if (clientCert.isEmpty() || clientKey.isEmpty()) {
            throw new RuntimeException("Client certificates not found for instance: " + name);
        }

        // Use the correct file paths matching what's in the Nebula config
        uploadFileToLocalContainer(containerId, CONFIG_DIRECTORY + "/" + name + ".crt",
                clientCert.get().getContent().getBytes());
        uploadFileToLocalContainer(containerId, CONFIG_DIRECTORY + "/" + name + ".key",
                clientKey.get().getContent().getBytes());

        executeLocalCommand("docker exec " + containerId + " chmod 644 " + CONFIG_DIRECTORY + "/" + name + ".crt");
        executeLocalCommand("docker exec " + containerId + " chmod 600 " + CONFIG_DIRECTORY + "/" + name + ".key");
    }

    private void uploadNebulaCACertToContainer(String containerId) throws Exception {
        Optional<Secret> caCertSecret = secretsService.getSecretByName("nebula_ca_cert");
        if (caCertSecret.isEmpty()) {
            throw new EntityNotFoundException("Nebula CA certificate not found");
        }
        uploadFileToLocalContainer(containerId, CONFIG_DIRECTORY + "/ca.crt",
                caCertSecret.get().getContent().getBytes());
    }

    private void uploadNebulaExecutableToContainer(String containerId) throws Exception {
        try (InputStream nebulaBinaryStream = resourceLoader.getResource(NEBULA_BINARY_PATH).getInputStream()) {
            byte[] nebulaBinaryContent = nebulaBinaryStream.readAllBytes();
            String tempFile = "/tmp/nebula_binary_" + System.currentTimeMillis();
            Files.write(Paths.get(tempFile), nebulaBinaryContent);
            String copyCommand = "docker cp " + tempFile + " " + containerId + ":/usr/local/bin/nebula";
            executeLocalCommand(copyCommand);
            Files.delete(Paths.get(tempFile));
            executeLocalCommand("docker exec " + containerId + " chmod +x /usr/local/bin/nebula");
        } catch (IOException e) {
            throw new RuntimeException("Failed to upload Nebula binary", e);
        }
    }

    private void startNebulaProcessInContainer(String containerId) throws Exception {
        String startCommand = "docker exec " + containerId + " nohup /usr/local/bin/nebula -config " + CONFIG_DIRECTORY
                + "/config.yml > /var/log/nebula.log 2>&1 &";
        executeLocalCommand(startCommand);
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
        StringBuilder errorOutput = new StringBuilder();

        try (BufferedReader stdout = new BufferedReader(new InputStreamReader(process.getInputStream()));
                BufferedReader stderr = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {

            String line;
            while ((line = stdout.readLine()) != null) {
                output.append(line).append("\n");
                logger.info("STDOUT: {}", line);
            }
            while ((line = stderr.readLine()) != null) {
                errorOutput.append(line).append("\n");
                logger.error("STDERR: {}", line);
            }
        }

        try {
            int exitCode = process.waitFor();
            logger.info("Command '{}' exited with code {}", command, exitCode);

            if (exitCode != 0 && !command.contains("|| true")) {
                String errorMsg = errorOutput.toString().trim();
                if (errorMsg.isEmpty()) {
                    errorMsg = "Unknown error";
                }
                logger.error("Command failed with exit code: {} and error: {}", exitCode, errorMsg);
                throw new RuntimeException("Command failed with exit code: " + exitCode + ". Error: " + errorMsg);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Command execution interrupted", e);
        }

        return output.toString();
    }

    /**
     * Executes a command locally on the host machine, piping input to the command.
     *
     * @param command     The command array to execute (e.g., ["sudo", "tee",
     *                    "/path/to/file"])
     * @param input       The byte array to pipe into the command's stdin
     * @param explanation Optional explanation for logging
     * @return The combined stdout and stderr of the command
     * @throws IOException          If an I/O error occurs
     * @throws InterruptedException If the command execution is interrupted
     */
    private String executeLocalCommandWithInput(String[] command, byte[] input, String explanation)
            throws IOException, InterruptedException {
        String commandString = String.join(" ", command);
        logger.info("Executing local command with input: {} {}", commandString,
                (explanation != null ? "(" + explanation + ")" : ""));

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        // Do NOT redirectErrorStream(true) here, we want to capture stderr separately
        // if needed
        Process process = processBuilder.start();

        // Write input to the process's stdin in a separate thread or carefully
        try (OutputStream stdin = process.getOutputStream()) {
            stdin.write(input);
        } catch (IOException e) {
            // This can happen if the process terminates quickly (e.g., command error)
            logger.warn("IOException writing to stdin for command '{}': {}. Process might have terminated.",
                    commandString, e.getMessage());
        }

        StringBuilder output = new StringBuilder();
        StringBuilder errorOutput = new StringBuilder();

        // Read stdout and stderr in separate threads to avoid blocking
        Thread outReaderThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                    logger.info("STDOUT: {}", line);
                }
            } catch (IOException e) {
                logger.error("Error reading STDOUT from command '{}': {}", commandString, e.getMessage());
            }
        });

        Thread errReaderThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    errorOutput.append(line).append("\n");
                    logger.error("STDERR: {}", line);
                }
            } catch (IOException e) {
                logger.error("Error reading STDERR from command '{}': {}", commandString, e.getMessage());
            }
        });

        outReaderThread.start();
        errReaderThread.start();

        int exitCode = process.waitFor();
        outReaderThread.join(); // Wait for reader threads to finish
        errReaderThread.join();

        logger.info("Command '{}' exited with code {}", commandString, exitCode);

        String combinedOutput = output.toString() + errorOutput.toString();

        // Consider || true logic if needed, but tee should generally work or fail
        // clearly
        if (exitCode != 0) {
            String errorMsg = errorOutput.toString().trim();
            if (errorMsg.isEmpty()) {
                errorMsg = "Command returned non-zero exit code with no stderr output.";
            }
            logger.error("Command failed with exit code: {} and error: {}", exitCode, errorMsg);
            // Throw exception for piping commands as failure usually indicates a problem
            throw new RuntimeException("Command failed with exit code: " + exitCode + ". Error: " + errorMsg);
        }

        return combinedOutput; // Return combined output, though often not needed for tee
    }

    private void uploadFileToLocalContainer(String containerId, String destPath, byte[] content) throws Exception {
        logger.info("Uploading content directly to container {} at {}", containerId, destPath);

        // Command to write content to the destination path inside the container
        // Using sh -c to handle the redirection correctly
        String[] command = {
                "docker", "exec", "-i", // -i is crucial for piping stdin
                containerId,
                "sh", "-c", "cat > " + destPath // Simple redirection
        };

        // Use the existing helper to execute and pipe the content
        executeLocalCommandWithInput(command, content, "Upload to container " + containerId + ":" + destPath);

        logger.info("Successfully uploaded content to container {} at {}", containerId, destPath);
    }

    // Overload for String content
    private void uploadFileToLocalContainer(String containerId, String destPath, String content) throws Exception {
        uploadFileToLocalContainer(containerId, destPath, content.getBytes());
    }

    // Event listeners
    @EventListener
    public void handleSwarmManagerInitializedEvent(SwarmManagerInitializedEvent event) {
        logger.info("Received SwarmManagerInitializedEvent. Source: {}, isHostSwarmManager: {}",
                event.getSource().getClass().getSimpleName(), event.isHostSwarmManager());

        // We now only support host-based swarm managers
        if (!event.isHostSwarmManager()) {
            logger.warn("Received SwarmManagerInitializedEvent for non-host swarm manager - ignoring as legacy case");
            return;
        }

        HostServer hostServer = event.getHostServer();
        if (hostServer == null) {
            logger.error("Host server is null in SwarmManagerInitializedEvent");
            return;
        }

        // Check if deployment is already in progress before acquiring lock
        if (HOST_DEPLOYMENT_IN_PROGRESS.get()) {
            logger.info("Host Nebula deployment already in progress - skipping duplicate deployment request");
            return;
        }

        synchronized (HOST_DEPLOYMENT_LOCK) {
            // Double-check inside synchronized block
            if (HOST_DEPLOYMENT_IN_PROGRESS.get()) {
                logger.info(
                        "Host Nebula deployment already in progress (rechecked) - skipping duplicate deployment request");
                return;
            }

            logger.info("Handling SwarmManagerInitializedEvent for host-based swarm manager: {}", hostServer.getId());

            // The most important check: if Nebula is already deployed, verify it's actually
            // running
            if (hostServer.isNebulaDeployed()) {
                try {
                    boolean interfaceUp = isNebulaInterfaceUp(hostServer.getVpn().getIp());
                    if (interfaceUp) {
                        logger.info(
                                "Nebula is already deployed and running on host server: {} - skipping duplicate deployment",
                                hostServer.getId());
                        return;
                    } else {
                        logger.warn("Nebula marked as deployed but interface is not up; continuing with deployment");
                    }
                } catch (Exception e) {
                    logger.warn("Error checking Nebula interface: {}", e.getMessage());
                }
            }

            // If this event comes from SwarmManagerDeploymentListener, it likely already
            // attempted Nebula deployment
            // This helps break the circular dependency
            if (event.getSource().getClass().getSimpleName().equals("SwarmManagerDeploymentListener")) {
                logger.info("Event from SwarmManagerDeploymentListener - checking nebula interface status");

                try {
                    boolean interfaceUp = isNebulaInterfaceUp(hostServer.getVpn().getIp());
                    if (interfaceUp) {
                        logger.info("Nebula interface is already up - skipping deployment");
                        hostServer.setNebulaDeployed(true);
                        hostServerService.markNebulaDeployed(hostServer);
                        return;
                    }
                } catch (Exception e) {
                    logger.warn("Error checking Nebula interface, will attempt deployment: {}", e.getMessage());
                }
            }

            // Set deployment in progress flag before starting
            HOST_DEPLOYMENT_IN_PROGRESS.set(true);

            try {
                // Deploy Nebula to the host
                logger.info("Deploying Nebula to host server: {} as part of SwarmManagerInitializedEvent handling",
                        hostServer.getId());

                deployNebulaToHost(hostServer)
                        .thenAccept(v -> {
                            logger.info("Nebula deployed successfully to host server: {}", hostServer.getId());

                            // Mark the host as having Nebula deployed
                            hostServerService.markNebulaDeployed(hostServer);

                            // Reset deployment in progress flag
                            HOST_DEPLOYMENT_IN_PROGRESS.set(false);
                        })
                        .exceptionally(ex -> {
                            logger.error("Failed to deploy Nebula to host machine", ex);

                            // Reset deployment in progress flag
                            HOST_DEPLOYMENT_IN_PROGRESS.set(false);
                            return null;
                        });
            } catch (Exception e) {
                logger.error("Exception in handling SwarmManagerInitializedEvent for host", e);

                // Reset deployment in progress flag on exception
                HOST_DEPLOYMENT_IN_PROGRESS.set(false);
            }
        }
    }

    @EventListener
    public void handleDeployNebulaEvent(DeployNebulaEvent event) {
        logger.info("Received DeployNebulaEvent for server ID: {}", event.getServerId());

        // Get the server ID to track deployment status
        Long serverId = event.getServerId();

        // Get the server-specific deployment flag
        AtomicBoolean deploymentFlag = getServerDeploymentFlag(serverId);

        // Check if deployment is already in progress
        if (deploymentFlag.get()) {
            logger.info("Nebula deployment already in progress for server ID: {} - skipping duplicate deployment",
                    serverId);
            return;
        }

        // Get the server-specific lock
        Object lock = getServerLock(serverId);

        // Use the lock to ensure thread safety
        synchronized (lock) {
            // Double-check inside synchronized block
            if (deploymentFlag.get()) {
                logger.info(
                        "Nebula deployment already in progress for server ID: {} (rechecked) - skipping duplicate deployment",
                        serverId);
                return;
            }

            // Mark deployment as in progress
            deploymentFlag.set(true);

            try {
                // Check if server is local
                Server server = getServerById(serverId);
                boolean isLocal = server.getInstance() != null &&
                        server.getInstance().getProvider() != null &&
                        "Local".equals(server.getInstance().getProvider().getName());

                if (isLocal) {
                    deployNebulaToLocalInstance(event.getServerId(), event.getNebulaConfigId())
                            .thenAccept(aVoid -> {
                                logger.info("Nebula deployed successfully for local server ID: {}",
                                        event.getServerId());
                                deploymentFlag.set(false);
                            })
                            .exceptionally(ex -> {
                                logger.error("Failed to deploy Nebula for local server ID: {}", event.getServerId(),
                                        ex);
                                deploymentFlag.set(false);
                                return null;
                            });
                } else {
                    deployNebulaToInstance(event.getServerId(), event.getNebulaConfigId())
                            .thenAccept(aVoid -> {
                                logger.info("Nebula deployed successfully for server ID: {}", event.getServerId());
                                deploymentFlag.set(false);
                            })
                            .exceptionally(ex -> {
                                logger.error("Failed to deploy Nebula for server ID: {}", event.getServerId(), ex);
                                deploymentFlag.set(false);
                                return null;
                            });
                }
            } catch (Exception e) {
                logger.error("Error handling DeployNebulaEvent", e);
                deploymentFlag.set(false);
            }
        }
    }

    @EventListener
    public void handleServerCreated(ServerCreatedEvent event) {
        Server server = event.getServer();

        // Check if this is a host-based server that might need to use
        // HOST_DEPLOYMENT_LOCK
        if (server.getInstance() == null) {
            // This might be a host deployment which should use the host lock
            if (HOST_DEPLOYMENT_IN_PROGRESS.get()) {
                logger.info("Host Nebula deployment already in progress - skipping ServerCreatedEvent deployment");
                return;
            }

            synchronized (HOST_DEPLOYMENT_LOCK) {
                if (HOST_DEPLOYMENT_IN_PROGRESS.get()) {
                    logger.info(
                            "Host Nebula deployment already in progress (rechecked) - skipping ServerCreatedEvent deployment");
                    return;
                }

                // Set flag to indicate host deployment in progress
                HOST_DEPLOYMENT_IN_PROGRESS.set(true);

                deployNebula(server)
                        .thenAccept(aVoid -> {
                            logger.info("Nebula deployed successfully for host server ID: {}", server.getId());
                            HOST_DEPLOYMENT_IN_PROGRESS.set(false);
                        })
                        .exceptionally(ex -> {
                            logger.error("Failed to deploy Nebula for host server ID: {}", server.getId(), ex);
                            HOST_DEPLOYMENT_IN_PROGRESS.set(false);
                            return null;
                        });
            }
        } else {
            // Regular server deployment (not host-based)
            Long serverId = server.getId();

            // Check if deployment is already in progress
            if (getServerDeploymentFlag(serverId).get()) {
                logger.info("Nebula deployment already in progress for server ID: {} - skipping duplicate deployment",
                        serverId);
                return;
            }

            // Get the server-specific lock
            Object lock = getServerLock(serverId);

            // Use the lock to ensure thread safety
            synchronized (lock) {
                // Double-check inside synchronized block
                if (getServerDeploymentFlag(serverId).get()) {
                    logger.info(
                            "Nebula deployment already in progress for server ID: {} (rechecked) - skipping duplicate deployment",
                            serverId);
                    return;
                }

                // Mark deployment as in progress
                getServerDeploymentFlag(serverId).set(true);

                try {
                    deployNebula(server)
                            .thenAccept(aVoid -> {
                                logger.info("Nebula deployed successfully for server ID: {}", server.getId());
                                getServerDeploymentFlag(serverId).set(false);
                            })
                            .exceptionally(ex -> {
                                logger.error("Failed to deploy Nebula for server ID: {}", server.getId(), ex);
                                getServerDeploymentFlag(serverId).set(false);
                                return null;
                            });
                } catch (Exception e) {
                    logger.error("Error handling ServerCreatedEvent", e);
                    getServerDeploymentFlag(serverId).set(false);
                }
            }
        }
    }

    public CompletableFuture<Void> deployNebula(Server server) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                Instance instance = server.getInstance();

                // Check if the server has a VPN configuration
                if (server.getVpn() == null) {
                    throw new IllegalStateException("Server " + server.getId() + " has no VPN configuration");
                }
                // Get the Nebula config ID *before* preparing deployment
                Long nebulaConfigId = server.getVpn().getId();
                if (nebulaConfigId == null) {
                    // This indicates a problem with how the server's VPN relationship was saved
                    throw new IllegalStateException("Server " + server.getId() + " VPN configuration has a null ID.");
                }

                // Determine if this is a host deployment (instance is null)
                boolean isHostDeployment = instance == null;
                boolean isLocal = !isHostDeployment && instance != null
                        && "Local".equals(instance.getProvider().getName());

                // Prepare deployment context
                DeploymentContext context;
                try {
                    // Pass the known valid ID
                    context = prepareDeployment(server.getId(), nebulaConfigId);
                } catch (Exception e) {
                    cleanupFailedDeployment(server);
                    throw new CompletionException("Failed to prepare deployment for server " + server.getId(), e);
                }

                // Deploy based on instance type
                try {
                    if (isHostDeployment) {
                        // This case should ideally not publish NebulaDeployedEvent but
                        // HostNebulaDeployedEvent
                        logger.warn(
                                "deployNebula(Server) called for a host deployment scenario. This might indicate an issue.");
                        // deployNebula(null, null, context.nebulaConfigContent()); // Assuming host
                        // deployment handled elsewhere
                    } else if (isLocal) {
                        deployNebulaToLocalContainer(instance, context.nebulaConfig(), context.nebulaConfigContent());
                    } else {
                        deployNebula(instance, context.sshKey(), context.nebulaConfigContent());
                    }
                } catch (Exception e) {
                    cleanupFailedDeployment(server);
                    throw new CompletionException("Failed to deploy Nebula to server " + server.getId(), e);
                }

                // If this is a lighthouse, publish the event
                // Check context.nebulaConfig() state *after* deployment logic
                if (context.nebulaConfig() != null && context.nebulaConfig().getLighthouse()) {
                    // Ensure the config object from context still has an ID if needed here
                    Long lighthouseConfigId = context.nebulaConfig().getId() != null ? context.nebulaConfig().getId()
                            : nebulaConfigId;
                    eventPublisher.publishEvent(new LighthouseNebulaDeployedEvent(this, context.nebulaConfig())); // Assuming
                                                                                                                  // Lighthouse
                                                                                                                  // event
                                                                                                                  // doesn't
                                                                                                                  // need
                                                                                                                  // the
                                                                                                                  // ID
                                                                                                                  // directly
                                                                                                                  // for
                                                                                                                  // listeners
                    logger.info("Published LighthouseNebulaDeployedEvent for Nebula ID: {}", lighthouseConfigId);
                } else if (!isHostDeployment) { // Only publish NebulaDeployedEvent for non-host, non-lighthouse
                    // For non-lighthouse servers, publish a general deployment event to trigger
                    // Docker Swarm join
                    // Convert numeric ID to a deterministic UUID to avoid format errors
                    UUID serverUuid = new UUID(0, server.getId());
                    // *** Use the original nebulaConfigId that was passed to prepareDeployment ***
                    eventPublisher.publishEvent(new NebulaDeployedEvent(this, serverUuid, nebulaConfigId));
                    logger.info(
                            "Published NebulaDeployedEvent for server {} with config ID {} to trigger Docker Swarm join",
                            server.getId(), nebulaConfigId); // Log the ID being published
                }

                // Mark Nebula as deployed on the server entity if applicable (might need
                // adjustment)
                // server.setNebulaDeployed(true); // Or similar flag
                // serverRepository.save(server); // Ensure state is saved

                logger.info("Nebula deployed successfully to server: {}", server.getId()); // Moved log message

                return null;
            } catch (Exception e) {
                // Log the specific server ID in case of failure
                logger.error("Failed to deploy Nebula to server: {}", server != null ? server.getId() : "UNKNOWN", e);
                // Do not call cleanup here if it's already called in inner catches
                throw new CompletionException("Failed to deploy Nebula", e);
            }
        }, executorService);
    }

    private void cleanupFailedDeployment(Server server) {
        logger.info("Cleaning up after failed deployment for server: {}", server.getId());
        try {
            // Delete any generated client certificates
            if (server.getInstance() != null) {
                String instanceName = server.getInstance().getName();
                secretsService.deleteSecretByName("nebula_" + instanceName + "_cert");
                secretsService.deleteSecretByName("nebula_" + instanceName + "_key");
            } else {
                // This might be a host deployment
                secretsService.deleteSecretByName("nebula_host_cert");
                secretsService.deleteSecretByName("nebula_host_key");
            }

            // Clean up any uploaded files if they exist
            if (server.getInstance() != null && server.getInstance().getIp() != null
                    && server.getInstance().getSshKey() != null) {
                String host = server.getInstance().getIp().getHostAddress();
                String user = "root";
                String privateKeySecretName = server.getInstance().getSshKey().getPrivateKeySecretName(); // Use secret
                                                                                                          // name

                if (privateKeySecretName == null || privateKeySecretName.isEmpty()) {
                    logger.warn("Skipping remote cleanup for server {} because SSH key secret name is missing.",
                            server.getId());
                } else {
                    // Try to remove Nebula directory
                    try {
                        remoteCommandService.executeCommand(host, user, privateKeySecretName,
                                "rm -rf " + CONFIG_DIRECTORY, 10);
                    } catch (Exception e) {
                        logger.warn("Failed to clean up Nebula directory on host: {}", host, e);
                    }

                    // Try to remove Nebula binary
                    try {
                        remoteCommandService.executeCommand(host, user, privateKeySecretName,
                                "rm -f /usr/local/bin/nebula", 10);
                    } catch (Exception e) {
                        logger.warn("Failed to clean up Nebula binary on host: {}", host, e);
                    }
                }
            } else {
                // This might be a host deployment, clean up locally
                try {
                    boolean isRoot = isRunningAsRoot();
                    String rmDirCommand = isRoot ? "rm -rf " + CONFIG_DIRECTORY + " || true"
                            : "sudo rm -rf " + CONFIG_DIRECTORY + " || true";
                    String rmBinaryCommand = isRoot ? "rm -f /usr/local/bin/nebula || true"
                            : "sudo rm -f /usr/local/bin/nebula || true";
                    String killCommand = isRoot ? "pkill -f nebula || true" : "sudo pkill -f nebula || true";

                    executeLocalCommand(rmDirCommand);
                    executeLocalCommand(rmBinaryCommand);
                    executeLocalCommand(killCommand);
                    logger.info("Cleaned up Nebula files on host machine");
                } catch (Exception e) {
                    logger.warn("Failed to clean up Nebula files on host machine", e);
                }
            }
        } catch (Exception e) {
            logger.error("Error during cleanup of failed deployment for server: {}", server.getId(), e);
        }
    }

    // Helper classes
    private record DeploymentContext(Server server, Instance instance, Nebula nebulaConfig, String nebulaConfigContent,
            List<String> allowedRoles, SSHKey sshKey) {
    }

    public static class DeploymentException extends RuntimeException {
        public DeploymentException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class EntityNotFoundException extends RuntimeException {
        public EntityNotFoundException(String message) {
            super(message);
        }
    }

    /**
     * Deploys Nebula directly to the host machine.
     * This is used when the host machine itself is part of the Nebula network
     * and acts as the Docker Swarm manager.
     * 
     * @param hostServer The HostServer entity representing the host machine
     * @return A CompletableFuture that completes when the deployment is done
     */
    @Transactional
    public CompletableFuture<Void> deployNebulaToHost(HostServer hostServer) {
        return CompletableFuture.supplyAsync(() -> {
            // No need to set the flag here as it's already set by the caller
            synchronized (HOST_DEPLOYMENT_LOCK) {
                try {
                    logger.info("Deploying Nebula directly to host machine for HostServer ID: {}", hostServer.getId());

                    // Double check if already deployed and actually running - this is a failsafe
                    if (hostServer.isNebulaDeployed()) {
                        // Additional verification that interface is up
                        try {
                            boolean interfaceUp = isNebulaInterfaceUp(hostServer.getVpn().getIp());
                            if (interfaceUp) {
                                logger.info("Nebula already deployed and running on host server: {}",
                                        hostServer.getId());
                                // Publish event even for existing deployment so other components know Nebula is
                                // ready
                                eventPublisher.publishEvent(new HostNebulaDeployedEvent(this, hostServer, true));
                                return null;
                            } else {
                                logger.warn("Nebula marked as deployed but interface is not up; redeploying");
                            }
                        } catch (Exception e) {
                            logger.warn("Error checking Nebula interface status; proceeding with deployment", e);
                        }
                    }

                    // CRITICAL: Always thoroughly clean up existing Nebula resources first
                    cleanupExistingNebulaInterface();

                    // Get the Nebula configuration
                    Nebula nebulaConfig = hostServer.getVpn();
                    if (nebulaConfig == null) {
                        throw new IllegalStateException("HostServer does not have Nebula configuration");
                    }

                    // Generate client certificates with retry mechanism
                    // This will automatically ensure the CA exists
                    List<String> allowedRoles = getAllowedRoles(nebulaConfig);

                    logger.info("Generating certificates for host with Nebula IP: {}", nebulaConfig.getIp());
                    generateClientCertWithRetry(null, nebulaConfig, allowedRoles);

                    // Verify client certificates exist
                    Optional<Secret> clientCert = secretsService.getSecretByName("nebula_host_cert");
                    Optional<Secret> clientKey = secretsService.getSecretByName("nebula_host_key");

                    if (clientCert.isEmpty() || clientKey.isEmpty()) {
                        logger.error("Client certificates not found after generation. Cert exists: {}, Key exists: {}",
                                clientCert.isPresent(), clientKey.isPresent());

                        // List existing certificates in the database to help troubleshoot
                        try {
                            logger.info("Listing all nebula-related secrets to help diagnose the issue:");
                            secretsService.getAllSecrets().stream()
                                    .filter(s -> s.getName().startsWith("nebula_"))
                                    .forEach(s -> logger.info("Found secret: {}", s.getName()));
                        } catch (Exception e) {
                            logger.error("Error listing secrets", e);
                        }

                        throw new RuntimeException("Client certificates not found after generation");
                    }

                    logger.info("Client certificates verified to exist");

                    // Generate Nebula config content
                    Map<String, String> lighthouseIpMap = getLighthouseIpMap(nebulaConfig);
                    String nebulaConfigContent = generateNebulaConfig(nebulaConfig, null, lighthouseIpMap);

                    // Log the full config for diagnostics
                    logger.debug("Generated Nebula config for host: {}", nebulaConfigContent);

                    // Use our updated deployNebula method to handle the host deployment
                    try {
                        logger.info("Using deployNebula method for host deployment");
                        deployNebula(null, null, nebulaConfigContent);
                    } catch (Exception e) {
                        logger.error("Failed to deploy Nebula to host", e);
                        throw new RuntimeException("Failed to deploy Nebula to host", e);
                    }

                    logger.info("Successfully deployed Nebula to host machine");

                    // Verify interface one more time before publishing event
                    boolean interfaceVerified = false;
                    try {
                        interfaceVerified = isNebulaInterfaceUp(nebulaConfig.getIp());
                        logger.info("Final Nebula interface verification result: {}", interfaceVerified);
                    } catch (Exception e) {
                        logger.warn("Error during final Nebula interface verification", e);
                    }

                    // Publish event signaling that Nebula has been deployed to the host
                    eventPublisher.publishEvent(new HostNebulaDeployedEvent(this, hostServer, interfaceVerified));

                    return null;
                } catch (Exception e) {
                    // Propagate the exception to be handled by the caller
                    throw new DeploymentException("Failed to deploy Nebula to host machine", e);
                }
            }
        }, executorService).thenAccept(v -> {
        });
    }

    /**
     * Checks if the application is running as root.
     * 
     * @return true if running as root, false otherwise
     */
    private boolean isRunningAsRoot() {
        try {
            String username = executeLocalCommand("whoami").trim();
            return "root".equals(username);
        } catch (Exception e) {
            logger.warn("Failed to determine if running as root: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Cleans up any existing Nebula interface and processes to avoid "device or
     * resource busy" errors.
     * This should be called before attempting to deploy Nebula to ensure a clean
     * state.
     */
    private void cleanupExistingNebulaInterface() {
        logger.info("Cleaning up any existing Nebula interface and processes...");
        try {
            // First, try a gentle terminate with SIGTERM
            executeLocalCommand("pkill nebula || true");

            // Give the process a moment to shut down gracefully
            Thread.sleep(1000);

            // Then check if any process is still running and use SIGKILL if needed
            String checkProcess = executeLocalCommand("pgrep nebula || echo 'NOT_FOUND'");
            if (!checkProcess.contains("NOT_FOUND")) {
                logger.info("Nebula process still running, using SIGKILL to terminate it");
                executeLocalCommand("pkill -9 nebula || true");

                // Wait a bit longer after SIGKILL
                Thread.sleep(2000);
            }

            // Make sure the interface is down
            executeLocalCommand("ip link delete nebula1 2>/dev/null || true");

            // Verify cleanup was successful
            try {
                String interfaceCheck = executeLocalCommand("ip link show | grep nebula || echo 'NOT_FOUND'");
                if (!interfaceCheck.contains("NOT_FOUND")) {
                    logger.warn("Nebula interface still exists after cleanup: {}", interfaceCheck);
                } else {
                    logger.info("Verified Nebula interface was removed");
                }

                String processCheck = executeLocalCommand("pgrep -f nebula || echo 'NOT_FOUND'");
                if (!processCheck.contains("NOT_FOUND")) {
                    logger.warn("Nebula process still exists after cleanup: {}", processCheck);
                } else {
                    logger.info("Verified Nebula process was terminated");
                }
            } catch (Exception e) {
                logger.warn("Error verifying cleanup: {}", e.getMessage());
            }

            logger.info("Successfully cleaned up existing Nebula interface and processes");
        } catch (Exception e) {
            logger.warn("Error during Nebula interface cleanup: {}", e.getMessage());
            // Continue despite errors - we'll still try to deploy
        }
    }

    /**
     * Checks if the Nebula interface is up and has the correct IP.
     * This is an improved implementation that is more flexible about interface
     * state.
     * 
     * @param expectedIp The expected IP address
     * @return true if the interface exists with the correct IP, false otherwise
     */
    private boolean isNebulaInterfaceUp(String expectedIp) throws IOException {
        try {
            // Check if the interface exists and has the correct IP
            String checkCommand = "ip addr show dev nebula1 2>/dev/null || echo 'NOT_FOUND'";
            String result = executeLocalCommand(checkCommand);

            if (result.contains("NOT_FOUND")) {
                logger.info("Nebula interface not found");
                return false;
            }

            // Extract just the IP part without CIDR notation if present
            String plainExpectedIp = expectedIp.split("/")[0].trim();

            // More flexible IP check - just check if the plain IP is present
            boolean hasCorrectIp = result.contains("inet " + plainExpectedIp);

            if (!hasCorrectIp) {
                logger.info("Nebula interface is present but has wrong IP (expected: {})", plainExpectedIp);
                return false;
            }

            // Log the actual state for debugging
            if (result.contains("state UP")) {
                logger.info("Nebula interface is UP with correct IP: {}", plainExpectedIp);
            } else if (result.contains("state UNKNOWN")) {
                logger.info("Nebula interface has state UNKNOWN but correct IP: {}", plainExpectedIp);
            } else {
                logger.info("Nebula interface has non-standard state but correct IP: {}", plainExpectedIp);
            }

            // Verify connectivity by pinging the lighthouse if available
            try {
                // Get lighthouse IP(s) to test connectivity
                List<Nebula> lighthouses = nebulaRepository.findByLighthouseTrue();
                if (!lighthouses.isEmpty()) {
                    for (Nebula lighthouse : lighthouses) {
                        String lighthouseIp = lighthouse.getIp();
                        if (lighthouseIp != null && !lighthouseIp.isEmpty() && !lighthouseIp.equals(plainExpectedIp)) {
                            // Try pinging lighthouse via Nebula network
                            String pingCmd = "ping -c 1 -W 2 " + lighthouseIp
                                    + " > /dev/null 2>&1 || echo 'PING_FAILED'";
                            String pingResult = executeLocalCommand(pingCmd);

                            if (!pingResult.contains("PING_FAILED")) {
                                logger.info(
                                        "Successfully pinged lighthouse {} via Nebula network - connectivity confirmed",
                                        lighthouseIp);
                                // If ping works, we definitely have connectivity
                                return true;
                            } else {
                                logger.warn("Failed to ping lighthouse {} via Nebula network", lighthouseIp);
                                // Continue with next lighthouse or assume it's still working if interface
                                // exists with correct IP
                            }
                        }
                    }
                }
            } catch (Exception e) {
                logger.warn("Error testing Nebula connectivity to lighthouse: {}", e.getMessage());
                // Continue with interface check result
            }

            // If we couldn't verify connectivity but interface exists with correct IP,
            // consider it working
            return hasCorrectIp;
        } catch (Exception e) {
            logger.warn("Error checking Nebula interface status: {}", e.getMessage());
            // If we can't determine, assume it's not up
            return false;
        }
    }

    /**
     * Gets a lock object for the specified server ID.
     * 
     * @param serverId The server ID
     * @return The lock object
     */
    private Object getServerLock(Long serverId) {
        return serverLocks.computeIfAbsent(serverId, k -> new Object());
    }

    /**
     * Gets or creates an AtomicBoolean for tracking deployment status of a server.
     * 
     * @param serverId The server ID
     * @return The AtomicBoolean
     */
    private AtomicBoolean getServerDeploymentFlag(Long serverId) {
        return serverDeploymentFlags.computeIfAbsent(serverId, k -> new AtomicBoolean(false));
    }
}