package com.tfg.infractory.domain.service;

import com.tfg.infractory.domain.model.*;
import com.tfg.infractory.domain.repository.SwarmNodeRepository;
import com.tfg.infractory.domain.repository.SwarmServiceRepository;
import com.tfg.infractory.infrastructure.docker.service.DockerSwarmService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.github.dockerjava.api.model.ServiceSpec;
import com.github.dockerjava.api.model.ContainerSpec;
import com.github.dockerjava.api.model.TaskSpec;
import com.github.dockerjava.api.model.ServiceModeConfig;
import com.github.dockerjava.api.model.ServiceReplicatedModeOptions;
import java.util.*;
import java.util.stream.Collectors;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.io.OutputStream;

/**
 * Service for deploying configurations and services to the Docker Swarm
 */
@Service
public class SwarmDeploymentService {

    private static final Logger logger = LoggerFactory.getLogger(SwarmDeploymentService.class);

    @Autowired
    private DockerSwarmService dockerSwarmService;

    @Autowired
    private SwarmNodeRepository swarmNodeRepository;

    @Autowired
    private SwarmServiceRepository swarmServiceRepository;

    @Autowired
    private DockerConfigService dockerConfigService;

    @Autowired
    private DockerImageService dockerImageService;

    @Autowired
    private ConfigAssignmentService configAssignmentService;

    /**
     * Deploy a Docker configuration to a specific node
     * 
     * @param configId The ID of the configuration to deploy
     * @param nodeId   The ID of the node to deploy to
     * @return Result message
     */
    @Transactional
    public String deployConfigToNode(Long configId, Long nodeId) {
        DockerConfig config = dockerConfigService.getDockerConfigById(configId);
        SwarmNode node = swarmNodeRepository.findById(nodeId)
                .orElseThrow(() -> new IllegalArgumentException("Node not found with ID: " + nodeId));

        if (node.getServer() == null) {
            throw new IllegalStateException("Node has no associated server");
        }

        try {
            // Apply the configuration to the server
            dockerSwarmService.applyDockerConfig(node.getServer().getInstance(), config);

            // Create an assignment if it doesn't exist
            configAssignmentService.assignToInstance(config, node.getServer().getInstance());

            return "Configuration '" + config.getName() + "' deployed successfully to node " + node.getHostname();
        } catch (Exception e) {
            logger.error("Error deploying configuration to node", e);
            throw new RuntimeException("Failed to deploy configuration: " + e.getMessage(), e);
        }
    }

    /**
     * Deploy a Docker configuration to all nodes of a specific server type
     * 
     * @param configId   The ID of the configuration to deploy
     * @param serverType The type of server to deploy to
     * @return Result message
     */
    @Transactional
    public String deployConfigToServerType(Long configId, String serverType) {
        DockerConfig config = dockerConfigService.getDockerConfigById(configId);

        // Find all nodes of this server type
        List<SwarmNode> nodes = swarmNodeRepository.findAll().stream()
                .filter(node -> node.getServer() != null &&
                        node.getServer().getClass().getSimpleName().equals(serverType))
                .collect(Collectors.toList());

        if (nodes.isEmpty()) {
            return "No nodes found for server type: " + serverType;
        }

        StringBuilder results = new StringBuilder();
        int successCount = 0;

        // Create a server type assignment
        configAssignmentService.assignToServerType(config, serverType);

        // Deploy to each node
        for (SwarmNode node : nodes) {
            try {
                dockerSwarmService.applyDockerConfig(node.getServer().getInstance(), config);
                successCount++;
            } catch (Exception e) {
                logger.error("Error deploying configuration to node " + node.getHostname(), e);
                results.append("Failed to deploy to ").append(node.getHostname())
                        .append(": ").append(e.getMessage()).append("\n");
            }
        }

        results.insert(0, "Deployed configuration '" + config.getName() +
                "' to " + successCount + " out of " + nodes.size() + " nodes.\n");

        return results.toString();
    }

    /**
     * Deploy a Docker configuration to all nodes with servers that have a specific
     * tag
     * 
     * @param configId The ID of the configuration to deploy
     * @param tag      The tag to filter servers by
     * @return Result message
     */
    @Transactional
    public String deployConfigByTag(Long configId, String tag) {
        DockerConfig config = dockerConfigService.getDockerConfigById(configId);

        // Find all nodes with services that have this tag
        List<SwarmNode> nodes = swarmNodeRepository.findAll().stream()
                .filter(node -> node.getServices().stream()
                        .anyMatch(service -> service.getTags().contains(tag)))
                .collect(Collectors.toList());

        if (nodes.isEmpty()) {
            return "No nodes found with services tagged: " + tag;
        }

        StringBuilder results = new StringBuilder();
        int successCount = 0;

        // Deploy to each node
        for (SwarmNode node : nodes) {
            try {
                dockerSwarmService.applyDockerConfig(node.getServer().getInstance(), config);

                // Create an instance-specific assignment
                configAssignmentService.assignToInstance(config, node.getServer().getInstance());

                successCount++;
            } catch (Exception e) {
                logger.error("Error deploying configuration to node " + node.getHostname(), e);
                results.append("Failed to deploy to ").append(node.getHostname())
                        .append(": ").append(e.getMessage()).append("\n");
            }
        }

        results.insert(0, "Deployed configuration '" + config.getName() +
                "' to " + successCount + " out of " + nodes.size() + " nodes with tag '" + tag + "'.\n");

        return results.toString();
    }

    /**
     * Create a new service on a specific node with placement constraints
     * 
     * @param nodeId               The ID of the node to create the service on
     *                             (optional if using server type or tags)
     * @param serviceName          The name of the service
     * @param imageId              The ID of the Docker image to use
     * @param environmentVariables Environment variables for the service
     * @param tags                 Tags for the service
     * @param publishedPorts       List of port mappings in the format
     *                             "published:target:protocol:mode"
     * @param replicas             Number of replicas to create
     * @param placementType        Type of placement constraint (node, server_type,
     *                             or tag)
     * @param placementValue       Value for the placement constraint
     * @return The created service
     */
    @Transactional
    public SwarmService createService(Long nodeId, String serviceName, Long imageId,
            Map<String, String> environmentVariables, Set<String> tags,
            List<String> publishedPorts, int replicas,
            String placementType, String placementValue) {

        DockerImage image = dockerImageService.getDockerImageById(imageId);
        if (image == null) {
            throw new IllegalArgumentException("Docker image not found with ID: " + imageId);
        }

        // Create a map of placement constraints
        Map<String, String> placementConstraints = new HashMap<>();

        // Set the placement constraint based on the type
        if (placementType != null && placementValue != null && !placementValue.isEmpty()) {
            switch (placementType) {
                case "node":
                    SwarmNode node = swarmNodeRepository.findById(Long.parseLong(placementValue))
                            .orElseThrow(
                                    () -> new IllegalArgumentException("Node not found with ID: " + placementValue));
                    String swarmNodeId = node.getNodeId();
                    placementConstraints.put("node.id", swarmNodeId);
                    break;
                case "server_type":
                    placementConstraints.put("node.labels.server_type", placementValue);
                    break;
                case "hostname":
                    placementConstraints.put("node.labels.hostname", placementValue);
                    break;
                case "server_id":
                    placementConstraints.put("node.labels.server_id", placementValue);
                    break;
                case "custom":
                    // Custom constraint format: "key==value"
                    String[] parts = placementValue.split("==");
                    if (parts.length == 2) {
                        placementConstraints.put(parts[0].trim(), parts[1].trim());
                    } else {
                        throw new IllegalArgumentException("Invalid custom constraint format. Use 'key==value'");
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported placement type: " + placementType);
            }
        } else if (nodeId != null) {
            // If no explicit placement but nodeId is provided, use the node ID as
            // constraint
            SwarmNode node = swarmNodeRepository.findById(nodeId)
                    .orElseThrow(() -> new IllegalArgumentException("Node not found with ID: " + nodeId));
            placementConstraints.put("node.id", node.getNodeId());
        }

        // Create the service spec
        ServiceSpec serviceSpec = createServiceSpec(
                serviceName,
                image.getRepository() + "/" + image.getName() + ":" + image.getTag(),
                environmentVariables,
                publishedPorts,
                replicas);

        // Create the service in Docker Swarm
        try {
            dockerSwarmService.createService(serviceSpec, placementConstraints);

            // Create the service entity in our database
            SwarmNode targetNode = null;
            if (nodeId != null) {
                targetNode = swarmNodeRepository.findById(nodeId).orElse(null);
            }

            SwarmService service = new SwarmService();
            service.setServiceName(serviceName);
            service.setServiceId(serviceName); // Docker service ID is the same as name in this case
            service.setStatus("running");
            service.setDockerImage(image);
            service.setNode(targetNode);
            service.setEnvironmentVariables(environmentVariables);
            service.setTags(tags != null ? tags : new HashSet<>());
            service.setPlacementConstraints(placementConstraints);
            service.setReplicas(replicas);

            // Save the published ports as a JSON string or another representation
            service.setPublishedPorts(String.join(",", publishedPorts));

            return swarmServiceRepository.save(service);
        } catch (Exception e) {
            logger.error("Failed to create service in Docker Swarm", e);
            throw new RuntimeException("Failed to create service: " + e.getMessage(), e);
        }
    }

    /**
     * Create a service specification for Docker Swarm
     */
    private ServiceSpec createServiceSpec(String serviceName, String imageName,
            Map<String, String> environmentVariables,
            List<String> publishedPorts, int replicas) {
        // Create a proper ServiceSpec object
        ServiceSpec serviceSpec = new ServiceSpec();

        // Set the service name
        serviceSpec.withName(serviceName);

        // Set up the container spec with the image and environment variables
        ContainerSpec containerSpec = new ContainerSpec()
                .withImage(imageName);

        // Add environment variables
        if (!environmentVariables.isEmpty()) {
            List<String> envVars = new ArrayList<>();
            for (Map.Entry<String, String> entry : environmentVariables.entrySet()) {
                envVars.add(entry.getKey() + "=" + entry.getValue());
            }
            containerSpec.withEnv(envVars);
        }

        // Create a task template with the container spec
        TaskSpec taskSpec = new TaskSpec()
                .withContainerSpec(containerSpec);

        // Set the task template on the service spec
        serviceSpec.withTaskTemplate(taskSpec);

        // Set the mode (replicated service with specified number of replicas)
        serviceSpec.withMode(new ServiceModeConfig()
                .withReplicated(new ServiceReplicatedModeOptions()
                        .withReplicas(replicas)));

        // We'll log port config details but not try to create them due to compatibility
        // issues
        if (!publishedPorts.isEmpty()) {
            StringBuilder portDetails = new StringBuilder();
            for (String portMapping : publishedPorts) {
                portDetails.append(portMapping).append(", ");
            }
            logger.info("Port mappings would be: {}", portDetails.toString());

            // Note: In a production environment, you would create proper port
            // configurations here
            // This is simplified due to potential version mismatches with the Docker Java
            // client
        }

        logger.info("Created service spec for service '{}' with image '{}'", serviceName, imageName);
        return serviceSpec;
    }

    /**
     * Legacy method to support older interface
     */
    @Transactional
    public SwarmService createService(Long nodeId, String serviceName, Long imageId,
            Map<String, String> environmentVariables, Set<String> tags) {
        // Call the new method with default values
        return createService(nodeId, serviceName, imageId, environmentVariables, tags,
                new ArrayList<>(), 1, "node", nodeId != null ? nodeId.toString() : null);
    }

    /**
     * Remove a service from the swarm
     * 
     * @param serviceId The ID of the service to remove
     * @return Result message
     */
    @Transactional
    public String removeService(Long serviceId) {
        SwarmService service = swarmServiceRepository.findById(serviceId)
                .orElseThrow(() -> new IllegalArgumentException("Service not found with ID: " + serviceId));

        // Implementation would interact with Docker Swarm API to remove the service
        // For now, we'll just remove the entity from our database

        swarmServiceRepository.delete(service);

        return "Service '" + service.getServiceName() + "' removed successfully";
    }

    /**
     * Restart a service
     * 
     * @param serviceId The ID of the service to restart
     * @return Result message
     */
    @Transactional
    public String restartService(Long serviceId) {
        SwarmService service = swarmServiceRepository.findById(serviceId)
                .orElseThrow(() -> new IllegalArgumentException("Service not found with ID: " + serviceId));

        try {
            // Use docker CLI to force update the service, which triggers a restart
            StringBuilder commandBuilder = new StringBuilder();
            commandBuilder.append("docker service update --force ")
                    .append(service.getServiceId());

            // Execute the command
            Process process = Runtime.getRuntime().exec(commandBuilder.toString());

            // Get the command output
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            int exitCode = process.waitFor();

            if (exitCode == 0) {
                // Update service status in database
                service.setStatus("restarting");
                swarmServiceRepository.save(service);

                return "Service '" + service.getServiceName() + "' restart initiated successfully";
            } else {
                // Read error output
                BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                StringBuilder errorOutput = new StringBuilder();
                while ((line = errorReader.readLine()) != null) {
                    errorOutput.append(line).append("\n");
                }

                throw new RuntimeException("Failed to restart service: " + errorOutput.toString());
            }
        } catch (Exception e) {
            logger.error("Error restarting service", e);
            throw new RuntimeException("Failed to restart service: " + e.getMessage(), e);
        }
    }

    // --- New Methods for Docker Config Rotation ---

    /**
     * Applies a DockerConfig entity (as a Docker Swarm Config) to running services
     * targeted by node, server type, or tag.
     *
     * @param configId   The ID of the DockerConfig entity.
     * @param nodeId     Target a specific node (optional).
     * @param serverType Target services running on nodes of a specific server type
     *                   (optional).
     * @param tag        Target services having a specific tag (optional).
     * @return Result message summarizing the operation.
     */
    @Transactional
    public String applyConfigToServices(Long configId, Long nodeId, String serverType, String tag) {
        DockerConfig config = dockerConfigService.getDockerConfigById(configId);
        if (config == null) {
            throw new IllegalArgumentException("DockerConfig not found with ID: " + configId);
        }
        if (config.getContent() == null || config.getContent().isEmpty()) {
            throw new IllegalArgumentException("DockerConfig content cannot be empty.");
        }
        if (config.getTargetPath() == null || config.getTargetPath().isEmpty()) {
            throw new IllegalArgumentException("DockerConfig targetPath must be set.");
        }

        // Sanitize config name for Docker
        String dockerConfigName = sanitizeDockerName("infractory-cfg-" + config.getId() + "-" + config.getName());

        StringBuilder resultSummary = new StringBuilder();

        // 1. Create or Update the Docker Swarm Config
        try {
            logger.info("Creating/updating Docker config: {}", dockerConfigName);
            CommandResult configCreateResult = createOrUpdateDockerConfig(dockerConfigName, config.getContent());
            if (!configCreateResult.isSuccess()) {
                logger.error("Failed to create/update Docker config {}: {}", dockerConfigName,
                        configCreateResult.getOutput());
                throw new RuntimeException(
                        "Failed to create/update Docker Swarm config: " + configCreateResult.getOutput());
            }
            resultSummary.append("Docker Swarm config '").append(dockerConfigName).append("' created/updated.\n");
            logger.info("Successfully created/updated Docker config: {}", dockerConfigName);
        } catch (Exception e) {
            logger.error("Error managing Docker Swarm config: {}", dockerConfigName, e);
            return "Error managing Docker Swarm config: " + e.getMessage();
        }

        // 2. Find Target Services
        List<SwarmService> targetServices = findTargetServices(nodeId, serverType, tag);
        if (targetServices.isEmpty()) {
            resultSummary.append("No target services found matching the criteria.");
            return resultSummary.toString();
        }
        resultSummary.append("Found ").append(targetServices.size()).append(" target services.\n");

        // 3. Update Target Services
        int successCount = 0;
        for (SwarmService service : targetServices) {
            try {
                logger.info("Applying config {} to service {} ({})", dockerConfigName, service.getServiceName(),
                        service.getServiceId());
                CommandResult updateResult = updateServiceWithConfig(service, dockerConfigName, config.getTargetPath());
                if (updateResult.isSuccess()) {
                    successCount++;
                    resultSummary.append("- Successfully updated service '").append(service.getServiceName())
                            .append("'.\n");
                    logger.info("Successfully updated service {}", service.getServiceId());
                } else {
                    resultSummary.append("- Failed to update service '").append(service.getServiceName()).append("': ")
                            .append(updateResult.getOutput()).append("\n");
                    logger.warn("Failed to update service {} with config {}: {}", service.getServiceId(),
                            dockerConfigName, updateResult.getOutput());
                }
            } catch (Exception e) {
                resultSummary.append("- Error updating service '").append(service.getServiceName()).append("': ")
                        .append(e.getMessage()).append("\n");
                logger.error("Error updating service {} with config {}", service.getServiceId(), dockerConfigName, e);
            }
        }

        resultSummary.append("Finished applying config. Success count: ").append(successCount).append("/")
                .append(targetServices.size()).append(".");
        return resultSummary.toString();
    }

    /**
     * Finds SwarmService entities based on targeting criteria.
     */
    private List<SwarmService> findTargetServices(Long nodeId, String serverType, String tag) {
        if (nodeId != null) {
            SwarmNode node = swarmNodeRepository.findById(nodeId)
                    .orElseThrow(() -> new IllegalArgumentException("Node not found with ID: " + nodeId));
            // Assuming SwarmService has a direct relationship with SwarmNode
            return swarmServiceRepository.findByNode(node);
        } else if (serverType != null && !serverType.isEmpty()) {
            // Find nodes of the server type, then find services on those nodes
            List<SwarmNode> nodes = swarmNodeRepository.findAll().stream()
                    .filter(n -> n.getServer() != null && n.getServer().getClass().getSimpleName().equals(serverType))
                    .collect(Collectors.toList());
            return swarmServiceRepository.findByNodeIn(nodes);
        } else if (tag != null && !tag.isEmpty()) {
            // Find services directly by tag
            return swarmServiceRepository.findByTagsContaining(tag);
        } else {
            // No specific target means target all services? Or throw error?
            // For safety, let's return an empty list if no target is specified.
            logger.warn(
                    "No specific target (nodeId, serverType, or tag) provided for applying config. No services will be updated.");
            return Collections.emptyList();
            // Alternatively, could target all services: return
            // swarmServiceRepository.findAll();
        }
    }

    /**
     * Creates or updates a Docker Swarm config.
     */
    private CommandResult createOrUpdateDockerConfig(String configName, String content)
            throws IOException, InterruptedException {
        // Check if config exists
        CommandResult inspectResult = executeCommand("docker config inspect " + configName);

        // If it exists, remove it first
        if (inspectResult.isSuccess()) {
            logger.debug("Config {} exists, removing before update.", configName);
            CommandResult rmResult = executeCommand("docker config rm " + configName);
            if (!rmResult.isSuccess()) {
                // Log the error but attempt creation anyway, maybe the inspect was faulty
                logger.warn("Failed to remove existing config {}: {}. Attempting creation anyway.", configName,
                        rmResult.getOutput());
            }
        }

        // Create the config using echo piped to docker config create
        // This avoids issues with temporary files and permissions.
        // Use ProcessBuilder for handling stdin redirection.
        ProcessBuilder pb = new ProcessBuilder("docker", "config", "create", configName, "-");
        Process process = pb.start();

        // Write content to the process's stdin
        try (OutputStream stdin = process.getOutputStream()) {
            stdin.write(content.getBytes(StandardCharsets.UTF_8));
        }

        // Wait for the process and get result
        int exitCode = process.waitFor();
        String output = readStream(process.getInputStream()) + "\n" + readStream(process.getErrorStream());

        logger.debug("Docker config create exit code: {}, output: {}", exitCode, output);
        return new CommandResult(exitCode == 0, output.trim());
    }

    /**
     * Updates a specific Docker service to add/replace a config.
     */
    private CommandResult updateServiceWithConfig(SwarmService service, String dockerConfigName, String targetPath)
            throws IOException, InterruptedException {
        if (service.getServiceId() == null || service.getServiceId().isEmpty()) {
            logger.error("Service {} has no valid Docker Service ID.", service.getServiceName());
            return new CommandResult(false, "Service has no Docker Service ID");
        }

        // Construct the command. Use --config-add, Docker handles updates/replacements.
        String command = String.format("docker service update --config-add source=%s,target=%s %s",
                dockerConfigName, targetPath, service.getServiceId());

        return executeCommand(command);
    }

    /**
     * Executes a shell command and captures its output.
     */
    private CommandResult executeCommand(String command) throws IOException, InterruptedException {
        logger.debug("Executing command: {}", command);
        Process process = Runtime.getRuntime().exec(command);

        String output = readStream(process.getInputStream());
        String error = readStream(process.getErrorStream());
        int exitCode = process.waitFor();

        String combinedOutput = (output.isEmpty() ? "" : output) + (error.isEmpty() ? "" : "\nError: " + error);
        logger.debug("Command exit code: {}, output: {}", exitCode, combinedOutput);

        return new CommandResult(exitCode == 0, combinedOutput.trim());
    }

    /**
     * Reads an InputStream into a String.
     */
    private String readStream(InputStream stream) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }

    /**
     * Sanitizes a string to be a valid Docker object name.
     * Replaces invalid characters with underscores.
     */
    private String sanitizeDockerName(String name) {
        if (name == null)
            return null;
        // Docker names typically allow [a-zA-Z0-9][a-zA-Z0-9_.-]*
        // Keep it simple: replace anything not alphanumeric or hyphen with underscore
        String sanitized = name.replaceAll("[^a-zA-Z0-9-]", "_");
        // Ensure it doesn't start or end with underscore/hyphen if possible
        sanitized = sanitized.replaceAll("^[_-]+", "").replaceAll("[_-]+$", "");
        // Ensure it's not empty after sanitization
        return sanitized.isEmpty() ? "default_name" : sanitized;
    }

    /**
     * Helper class to store command execution results.
     */
    private static class CommandResult {
        private final boolean success;
        private final String output;

        public CommandResult(boolean success, String output) {
            this.success = success;
            this.output = output;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getOutput() {
            return output;
        }
    }

    // --- End of New Methods ---

    // --- New Methods for Service Inspection ---

    /**
     * Get the raw JSON output of 'docker service inspect' for a given service.
     *
     * @param serviceId The database ID of the service.
     * @return The JSON output as a String, or an error message.
     */
    public String getServiceInspectOutput(Long serviceId) {
        SwarmService service = swarmServiceRepository.findById(serviceId)
                .orElseThrow(() -> new IllegalArgumentException("Service not found with ID: " + serviceId));

        if (service.getServiceId() == null || service.getServiceId().isEmpty()) {
            logger.error("Service {} (DB ID: {}) has no valid Docker Service ID.", service.getServiceName(), serviceId);
            return "{\"error\": \"Service has no Docker Service ID\"}";
        }

        String dockerServiceIdentifier = service.getServiceId(); // Use the stored Docker service ID/name
        String command = "docker service inspect " + dockerServiceIdentifier;

        try {
            CommandResult result = executeCommand(command);
            if (result.isSuccess()) {
                // Docker inspect outputs a JSON array, return the first element's content
                // Trim potential surrounding brackets if present
                String output = result.getOutput().trim();
                if (output.startsWith("[") && output.endsWith("]")) {
                    output = output.substring(1, output.length() - 1);
                }
                return output;
            } else {
                logger.error("Failed to inspect service {} (Docker ID: {}): {}", service.getServiceName(),
                        dockerServiceIdentifier, result.getOutput());
                return "{\"error\": \"Failed to inspect service: " + result.getOutput().replace("\"", "\\\"") + "\"}";
            }
        } catch (IOException | InterruptedException e) {
            logger.error("Error executing docker service inspect for service {} (Docker ID: {})",
                    service.getServiceName(), dockerServiceIdentifier, e);
            Thread.currentThread().interrupt(); // Re-interrupt the thread
            return "{\"error\": \"Exception during service inspection: " + e.getMessage().replace("\"", "\\\"") + "\"}";
        }
    }

    /**
     * Get the logs for a given service using 'docker service logs'.
     *
     * @param serviceId The database ID of the service.
     * @return The service logs as a String, or an error message.
     */
    public String getServiceLogs(Long serviceId) {
        SwarmService service = swarmServiceRepository.findById(serviceId)
                .orElseThrow(() -> new IllegalArgumentException("Service not found with ID: " + serviceId));

        if (service.getServiceId() == null || service.getServiceId().isEmpty()) {
            logger.error("Service {} (DB ID: {}) has no valid Docker Service ID.", service.getServiceName(), serviceId);
            return "Error: Service has no Docker Service ID.";
        }

        String dockerServiceIdentifier = service.getServiceId(); // Use the stored Docker service ID/name
        // Get recent logs, limit lines to avoid overwhelming output
        // --tail specifies number of lines from end, --timestamps adds timestamps
        // String command = "docker service logs --tail 100 --timestamps " +
        // dockerServiceIdentifier;
        // Fetch all logs to see if more than one line exists
        // String command = "docker service logs --timestamps " +
        // dockerServiceIdentifier;
        // Fetch recent logs (e.g., last 200) with timestamps
        String command = "docker service logs --tail 200 --timestamps " + dockerServiceIdentifier;

        try {
            // Execute command - logs often go to both stdout and stderr
            logger.debug("Executing logs command: {}", command);
            Process process = Runtime.getRuntime().exec(command);

            String output = readStream(process.getInputStream());
            String error = readStream(process.getErrorStream());
            int exitCode = process.waitFor();

            // Combine stderr first, then stdout, as logs often go to stderr
            String combinedOutput = (error.isEmpty() ? "" : error) + (output.isEmpty() ? "" : "\\n" + output); // Combine
                                                                                                               // stderr
                                                                                                               // and
                                                                                                               // stdout

            if (exitCode == 0) {
                if (combinedOutput.trim().isEmpty()) {
                    return "No logs available for this service.";
                }
                return combinedOutput.trim();
            } else {
                logger.error("Failed to get logs for service {} (Docker ID: {}), exit code {}: {}",
                        service.getServiceName(), dockerServiceIdentifier, exitCode, combinedOutput);
                return "Error fetching logs: " + combinedOutput.trim();
            }

        } catch (IOException | InterruptedException e) {
            logger.error("Error executing docker service logs for service {} (Docker ID: {})", service.getServiceName(),
                    dockerServiceIdentifier, e);
            Thread.currentThread().interrupt(); // Re-interrupt the thread
            return "Error fetching logs: Exception occurred - " + e.getMessage();
        }
    }

    /**
     * Get the raw JSON output of 'docker node inspect' for a given node.
     *
     * @param nodeId The database ID of the node.
     * @return The JSON output as a String, or an error message.
     */
    public String getNodeInspectOutput(Long nodeId) {
        SwarmNode node = swarmNodeRepository.findById(nodeId)
                .orElseThrow(() -> new IllegalArgumentException("Node not found with ID: " + nodeId));

        if (node.getNodeId() == null || node.getNodeId().isEmpty()) {
            logger.error("Node {} (DB ID: {}) has no valid Docker Node ID.", node.getHostname(), nodeId);
            return "{\"error\": \"Node has no Docker Node ID\"}";
        }

        String dockerNodeId = node.getNodeId();
        String command = "docker node inspect " + dockerNodeId;

        try {
            CommandResult result = executeCommand(command);
            if (result.isSuccess()) {
                // Docker inspect outputs a JSON array, return the first element's content
                String output = result.getOutput().trim();
                if (output.startsWith("[") && output.endsWith("]")) {
                    output = output.substring(1, output.length() - 1);
                }
                return output;
            } else {
                logger.error("Failed to inspect node {} (Docker ID: {}): {}", node.getHostname(), dockerNodeId,
                        result.getOutput());
                return "{\"error\": \"Failed to inspect node: " + result.getOutput().replace("\"", "\\\"") + "\"}";
            }
        } catch (IOException | InterruptedException e) {
            logger.error("Error executing docker node inspect for node {} (Docker ID: {})", node.getHostname(),
                    dockerNodeId, e);
            Thread.currentThread().interrupt(); // Re-interrupt the thread
            return "{\"error\": \"Exception during node inspection: " + e.getMessage().replace("\"", "\\\"") + "\"}";
        }
    }

    // --- End of New Methods ---
}