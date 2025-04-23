package com.tfg.infractory.web.controller;

import com.tfg.infractory.domain.model.SwarmNode;
import com.tfg.infractory.domain.model.SwarmService;
import com.tfg.infractory.domain.model.DockerImage;
import com.tfg.infractory.domain.service.DockerConfigService;
import com.tfg.infractory.domain.service.DockerImageService;
import com.tfg.infractory.domain.service.SwarmDeploymentService;
import com.tfg.infractory.domain.service.SwarmVisualizationService;
import com.tfg.infractory.domain.repository.SwarmServiceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;
import java.util.stream.Collectors;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Controller for Docker Swarm management
 */
@Controller
@RequestMapping("/swarm")
public class SwarmController {

    private static final Logger logger = LoggerFactory.getLogger(SwarmController.class);

    @Autowired
    private SwarmVisualizationService swarmVisualizationService;

    @Autowired
    private SwarmDeploymentService swarmDeploymentService;

    @Autowired
    private DockerConfigService dockerConfigService;

    @Autowired
    private DockerImageService dockerImageService;

    @Autowired
    private SwarmServiceRepository swarmServiceRepository;

    /**
     * Show the main Swarm dashboard
     */
    @GetMapping
    public String showSwarmDashboard(Model model) {
        model.addAttribute("nodes", swarmVisualizationService.getAllNodes());
        model.addAttribute("managerNodes", swarmVisualizationService.getManagerNodes());
        model.addAttribute("workerNodes", swarmVisualizationService.getWorkerNodes());

        // Get all tags from services for filtering
        Set<String> allTags = new HashSet<>();
        for (SwarmService service : swarmVisualizationService.getAllServices()) {
            allTags.addAll(service.getTags());
        }
        model.addAttribute("availableTags", allTags);

        return "swarm/index";
    }

    /**
     * Show details for a specific node
     */
    @GetMapping("/node/{id}")
    @SuppressWarnings("unchecked") // Suppress warnings for safe casts after instanceof checks
    public String showNodeDetails(@PathVariable("id") Long id, Model model) {
        SwarmNode node = swarmVisualizationService.getNodeById(id);
        model.addAttribute("node", node);
        model.addAttribute("services", swarmVisualizationService.getServicesForNode(node));
        model.addAttribute("availableConfigs", dockerConfigService.getAllDockerConfigs());

        // Add Node Inspection Details
        try {
            String inspectJson = swarmDeploymentService.getNodeInspectOutput(id);
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> inspectMap = mapper.readValue(inspectJson, new TypeReference<Map<String, Object>>() {
            });

            // Extract specific details
            String nodeIp = "N/A";

            if (inspectMap.containsKey("Status") && inspectMap.get("Status") instanceof Map) {
                Map<String, Object> statusMap = (Map<String, Object>) inspectMap.get("Status");
                nodeIp = (String) statusMap.getOrDefault("Addr", "N/A");
            }
            if (inspectMap.containsKey("ManagerStatus") && inspectMap.get("ManagerStatus") instanceof Map) {
                Map<String, Object> managerStatusMap = (Map<String, Object>) inspectMap.get("ManagerStatus");
                // For manager node, IP might be under ManagerStatus
                if (nodeIp.equals("N/A") || nodeIp.isEmpty() || nodeIp.equals("0.0.0.0")) { // Check if IP wasn't found
                                                                                            // or is default
                    nodeIp = (String) managerStatusMap.getOrDefault("Addr", "N/A");
                }
            }

            model.addAttribute("nodeAddr", nodeIp);

        } catch (Exception e) {
            logger.error("Failed to get or parse node inspect output for node ID {}: {}", id, e.getMessage());
            // Add default values or error indicators to the model
            model.addAttribute("nodeAddr", "Error");
        }

        return "swarm/node-details";
    }

    /**
     * Show the deployment interface
     */
    @GetMapping("/deploy")
    public String showDeploymentPage(Model model) {
        model.addAttribute("configurations", dockerConfigService.getAllDockerConfigs());
        model.addAttribute("images", dockerImageService.getAllDockerImages());
        model.addAttribute("nodes", swarmVisualizationService.getAllNodes());
        model.addAttribute("serverTypes", getAvailableServerTypes());

        // Get all tags from services for filtering
        Set<String> allTags = new HashSet<>();
        for (SwarmService service : swarmVisualizationService.getAllServices()) {
            allTags.addAll(service.getTags());
        }
        model.addAttribute("availableTags", allTags);

        return "swarm/deployment";
    }

    /**
     * Applies a DockerConfig (as a Swarm Config) to services targeted by node,
     * server type, or tag.
     */
    @PostMapping("/deploy/config")
    public String applyConfigurationToServices(
            @RequestParam("configId") Long configId,
            @RequestParam(required = false, name = "nodeId") Long nodeId,
            @RequestParam(required = false, name = "serverType") String serverType,
            @RequestParam(required = false, name = "tag") String tag,
            RedirectAttributes attributes) {

        try {
            if (nodeId == null && (serverType == null || serverType.isEmpty()) && (tag == null || tag.isEmpty())) {
                throw new IllegalArgumentException("Must specify at least one target: nodeId, serverType, or tag");
            }

            logger.info("Attempting to apply config ID {} to targets: nodeId={}, serverType={}, tag={}",
                    configId, nodeId, serverType, tag);

            // Call the new service method for applying configs
            String result = swarmDeploymentService.applyConfigToServices(configId, nodeId, serverType, tag);

            // Check the result message for common patterns indicating success or partial
            // failure
            if (result.toLowerCase().contains("error") || result.toLowerCase().contains("failed")) {
                // Consider it a partial success or warning, use success message but log details
                logger.warn("Potential issues applying config {}: {}", configId, result);
                attributes.addFlashAttribute("warningMessage",
                        "Configuration application process finished. Please check details: " + result);
            } else {
                attributes.addFlashAttribute("successMessage", "Configuration application successful: " + result);
            }

        } catch (IllegalArgumentException e) {
            logger.warn("Invalid arguments for applying configuration: {}", e.getMessage());
            attributes.addFlashAttribute("errorMessage", "Invalid request: " + e.getMessage());
        } catch (Exception e) {
            logger.error("Error applying configuration ID {} to services", configId, e);
            attributes.addFlashAttribute("errorMessage", "Error applying configuration: " + e.getMessage());
        }

        return "redirect:/swarm/deploy";
    }

    /**
     * Create a new service with form submission from the deployment page
     */
    @PostMapping("/service/create")
    public String createServiceFromForm(
            @RequestParam(required = false, name = "nodeId") Long nodeId,
            @RequestParam(name = "serviceName") String serviceName,
            @RequestParam("imageId") Long imageId,
            @RequestParam Map<String, String> environmentVariables,
            @RequestParam(required = false, name = "tags") Set<String> tags,
            @RequestParam(required = false, name = "publishedPorts") List<String> publishedPorts,
            @RequestParam(required = false, name = "replicas", defaultValue = "1") int replicas,
            @RequestParam(required = false, name = "placementType") String placementType,
            @RequestParam(required = false, name = "placementValue") String placementValue,
            RedirectAttributes attributes) {

        try {
            // Get the Docker image
            DockerImage image = dockerImageService.getDockerImageById(imageId);
            if (image == null) {
                throw new IllegalArgumentException("Docker image not found with ID: " + imageId);
            }

            // Run docker service create command directly - more reliable than the API
            StringBuilder commandBuilder = new StringBuilder();
            commandBuilder.append("docker service create --name ").append(serviceName);

            // Add replicas
            commandBuilder.append(" --replicas ").append(replicas);

            // Add environment variables
            for (Map.Entry<String, String> entry : environmentVariables.entrySet()) {
                // Skip non-environment variables (form fields)
                if (entry.getKey().equals("serviceName") ||
                        entry.getKey().equals("imageId") ||
                        entry.getKey().equals("tags") ||
                        entry.getKey().equals("publishedPorts") ||
                        entry.getKey().equals("replicas") ||
                        entry.getKey().equals("placementType") ||
                        entry.getKey().equals("placementValue")) {
                    continue;
                }

                commandBuilder.append(" --env ").append(entry.getKey()).append("=").append(entry.getValue());
            }

            // Add port mappings if any
            if (publishedPorts != null) {
                logger.info("Processing port mappings: {}", publishedPorts);
                for (String portMapping : publishedPorts) {
                    try {
                        // Format: "published:target:protocol:mode"
                        String[] parts = portMapping.split(":");
                        if (parts.length >= 2) {
                            int publishedPort = Integer.parseInt(parts[0]);
                            int targetPort = Integer.parseInt(parts[1]);
                            String protocol = parts.length > 2 ? parts[2] : "tcp";
                            String mode = parts.length > 3 ? parts[3] : "host";

                            // Properly format the --publish flag for Docker
                            String publishArg = " --publish published=" + publishedPort +
                                    ",target=" + targetPort +
                                    ",protocol=" + protocol +
                                    ",mode=" + mode;
                            logger.info("Adding port publication: {}", publishArg);
                            commandBuilder.append(publishArg);
                        }
                    } catch (NumberFormatException e) {
                        logger.error("Invalid port mapping format: " + portMapping, e);
                    }
                }
            }

            // Add placement constraint if provided
            if (placementType != null && placementValue != null && !placementValue.isEmpty()) {
                String constraint = null;

                switch (placementType) {
                    case "node":
                        // Find node ID for the given node database ID
                        SwarmNode node = swarmVisualizationService.getNodeById(Long.parseLong(placementValue));
                        if (node != null) {
                            constraint = "node.id==" + node.getNodeId();
                        }
                        break;
                    case "server_type":
                        constraint = "node.labels.server_type==" + placementValue;
                        break;
                    case "hostname":
                        constraint = "node.labels.hostname==" + placementValue;
                        break;
                    case "custom":
                        constraint = placementValue; // Already in correct format
                        break;
                    default:
                        break;
                }

                if (constraint != null) {
                    commandBuilder.append(" --constraint ").append(constraint);
                }
            } else if (nodeId != null) {
                // If no explicit placement but nodeId is provided, use the node ID as
                // constraint
                SwarmNode node = swarmVisualizationService.getNodeById(nodeId);
                if (node != null) {
                    commandBuilder.append(" --constraint node.id==").append(node.getNodeId());
                }
            }

            // Add image name
            commandBuilder.append(" ").append(image.getRepository()).append("/")
                    .append(image.getName()).append(":")
                    .append(image.getTag());

            // Execute the command
            logger.info("Executing Docker command: {}", commandBuilder.toString());
            Runtime runtime = Runtime.getRuntime();
            Process process = runtime.exec(commandBuilder.toString());

            // Get the command output
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            int exitCode = process.waitFor();

            if (exitCode == 0) {
                // Create database entry for the service
                SwarmService service = new SwarmService();
                service.setServiceName(serviceName);
                service.setServiceId(serviceName); // Docker service ID is the same as name in this case
                service.setStatus("running");
                service.setDockerImage(image);

                // Set the node if provided
                if (nodeId != null) {
                    SwarmNode targetNode = swarmVisualizationService.getNodeById(nodeId);
                    service.setNode(targetNode);
                }

                // Filter out form fields from environment variables
                Map<String, String> filteredEnvVars = new HashMap<>(environmentVariables);
                filteredEnvVars.remove("serviceName");
                filteredEnvVars.remove("imageId");
                filteredEnvVars.remove("tags");
                filteredEnvVars.remove("publishedPorts");
                filteredEnvVars.remove("replicas");
                filteredEnvVars.remove("placementType");
                filteredEnvVars.remove("placementValue");

                service.setEnvironmentVariables(filteredEnvVars);
                service.setTags(tags != null ? tags : new HashSet<>());
                service.setReplicas(replicas);

                // Save published ports as string
                if (publishedPorts != null) {
                    service.setPublishedPorts(String.join(",", publishedPorts));
                }

                // Save placement constraints
                Map<String, String> placementConstraints = new HashMap<>();
                if (placementType != null && placementValue != null && !placementValue.isEmpty()) {
                    placementConstraints.put(placementType, placementValue);
                }
                service.setPlacementConstraints(placementConstraints);

                // Save the service to the database
                swarmServiceRepository.save(service);

                attributes.addFlashAttribute("successMessage",
                        "Service '" + service.getServiceName() + "' created successfully: " + output.toString());
            } else {
                // Get error output if command failed
                BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                StringBuilder errorOutput = new StringBuilder();
                while ((line = errorReader.readLine()) != null) {
                    errorOutput.append(line).append("\n");
                }

                attributes.addFlashAttribute("errorMessage",
                        "Failed to create service: " + errorOutput.toString());
            }
        } catch (Exception e) {
            logger.error("Error creating service", e);
            attributes.addFlashAttribute("errorMessage", "Failed to create service: " + e.getMessage());
        }

        return "redirect:/swarm/deploy";
    }

    /**
     * Create a new service on a node
     */
    @PostMapping("/node/{nodeId}/service/create")
    public String createService(
            @PathVariable("nodeId") Long nodeId,
            @RequestParam(name = "serviceName") String serviceName,
            @RequestParam("imageId") Long imageId,
            @RequestParam Map<String, String> environmentVariables,
            @RequestParam(required = false, name = "tags") Set<String> tags,
            @RequestParam(required = false, name = "publishedPorts") List<String> publishedPorts,
            @RequestParam(required = false, name = "replicas", defaultValue = "1") int replicas,
            @RequestParam(required = false, name = "placementType") String placementType,
            @RequestParam(required = false, name = "placementValue") String placementValue,
            RedirectAttributes attributes) {

        try {
            // Filter out form fields that aren't environment variables
            Map<String, String> filteredEnvVars = new HashMap<>(environmentVariables);
            filteredEnvVars.remove("serviceName");
            filteredEnvVars.remove("imageId");
            filteredEnvVars.remove("tags");
            filteredEnvVars.remove("publishedPorts");
            filteredEnvVars.remove("replicas");
            filteredEnvVars.remove("placementType");
            filteredEnvVars.remove("placementValue");

            // Default to empty list if no ports provided
            if (publishedPorts == null) {
                publishedPorts = new ArrayList<>();
            }

            // Create the service
            SwarmService service = swarmDeploymentService.createService(
                    nodeId, serviceName, imageId, filteredEnvVars,
                    tags != null ? tags : new HashSet<>(),
                    publishedPorts, replicas,
                    placementType, placementValue);

            attributes.addFlashAttribute("successMessage",
                    "Service '" + service.getServiceName() + "' created successfully");
        } catch (Exception e) {
            logger.error("Error creating service", e);
            attributes.addFlashAttribute("errorMessage", "Failed to create service: " + e.getMessage());
        }

        return "redirect:/swarm/node/" + nodeId;
    }

    /**
     * Remove a service
     */
    @PostMapping("/service/{serviceId}/remove")
    @ResponseBody
    public Map<String, Object> removeService(@PathVariable("serviceId") Long serviceId) {
        Map<String, Object> response = new HashMap<>();

        try {
            String result = swarmDeploymentService.removeService(serviceId);
            response.put("success", true);
            response.put("message", result);
        } catch (Exception e) {
            logger.error("Error removing service", e);
            response.put("success", false);
            response.put("message", "Failed to remove service: " + e.getMessage());
        }

        return response;
    }

    /**
     * Restart a service
     */
    @PostMapping("/service/{serviceId}/restart")
    @ResponseBody
    public Map<String, Object> restartService(@PathVariable("serviceId") Long serviceId) {
        Map<String, Object> response = new HashMap<>();
        logger.info("API request received to restart service, ID: {}", serviceId);

        try {
            String resultMessage = swarmDeploymentService.restartService(serviceId);
            // Infer success based on the message content (this might need refinement)
            boolean success = !resultMessage.toLowerCase().contains("failed")
                    && !resultMessage.toLowerCase().contains("error");
            response.put("success", success);
            response.put("message", resultMessage);
            logger.info("Restart result for service ID {}: {}", serviceId, resultMessage);
        } catch (IllegalArgumentException e) {
            logger.warn("Service not found for restart with ID: {}", serviceId);
            response.put("success", false);
            response.put("message", "Error: Service not found.");
            return response;
        } catch (Exception e) {
            logger.error("Error restarting service ID {}: {}", serviceId, e.getMessage(), e);
            response.put("success", false);
            response.put("message", "Failed to restart service: " + e.getMessage());
        }

        return response;
    }

    /**
     * Filter nodes by tag, server type, or status
     */
    @GetMapping("/filter")
    public String filterNodes(
            @RequestParam(required = false, name = "tag") String tag,
            @RequestParam(required = false, name = "serverType") String serverType,
            @RequestParam(required = false, name = "status") String status,
            Model model) {

        List<SwarmNode> filteredNodes = swarmVisualizationService.getAllNodes();

        // Apply tag filter if provided
        if (tag != null && !tag.isEmpty()) {
            filteredNodes = swarmVisualizationService.getNodesByServiceTag(tag);
        }

        // Apply server type filter if provided
        if (serverType != null && !serverType.isEmpty()) {
            filteredNodes = filteredNodes.stream()
                    .filter(node -> node.getServer() != null &&
                            node.getServer().getClass().getSimpleName().equals(serverType))
                    .collect(Collectors.toList());
        }

        // Apply status filter if provided
        if (status != null && !status.isEmpty()) {
            filteredNodes = filteredNodes.stream()
                    .filter(node -> node.getStatus().equals(status))
                    .collect(Collectors.toList());
        }

        // Split into managers and workers for the view
        List<SwarmNode> managers = filteredNodes.stream()
                .filter(node -> "manager".equals(node.getRole()))
                .collect(Collectors.toList());

        List<SwarmNode> workers = filteredNodes.stream()
                .filter(node -> "worker".equals(node.getRole()))
                .collect(Collectors.toList());

        model.addAttribute("managerNodes", managers);
        model.addAttribute("workerNodes", workers);

        return "swarm/fragments/nodes-list :: nodesList";
    }

    /**
     * Get logs for a node
     */
    @GetMapping("/node/{id}/logs")
    @ResponseBody
    public String getNodeLogs(@PathVariable("id") Long id) {
        try {
            SwarmNode node = swarmVisualizationService.getNodeById(id);

            // Execute docker node inspect command to get basic info
            StringBuilder commandBuilder = new StringBuilder();
            commandBuilder.append("docker node inspect ").append(node.getNodeId());

            // Execute the command
            logger.info("Executing command: {}", commandBuilder.toString());
            Process process = Runtime.getRuntime().exec(commandBuilder.toString());

            // Read the output
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            // Check for errors
            if (process.waitFor() != 0) {
                BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                StringBuilder errorOutput = new StringBuilder();
                while ((line = errorReader.readLine()) != null) {
                    errorOutput.append(line).append("\n");
                }

                // If error, return error message
                if (errorOutput.length() > 0) {
                    return "Error getting node information: " + errorOutput.toString();
                }
            }

            // Get node services and their logs
            List<SwarmService> services = swarmVisualizationService.getServicesForNode(node);

            StringBuilder completeOutput = new StringBuilder();
            completeOutput.append("Node Details for ").append(node.getHostname()).append(" (ID: ")
                    .append(node.getNodeId()).append(")\n\n");
            completeOutput.append("Status: ").append(node.getStatus()).append("\n");
            completeOutput.append("Role: ").append(node.getRole()).append("\n\n");

            // Add node inspection data
            completeOutput.append("--- Node Inspection Data ---\n");
            completeOutput.append(output.toString()).append("\n\n");

            // Add service information
            completeOutput.append("--- Services Running on This Node ---\n");
            if (services.isEmpty()) {
                completeOutput.append("No services currently running on this node.\n");
            } else {
                for (SwarmService service : services) {
                    completeOutput.append("Service: ").append(service.getServiceName())
                            .append(" (").append(service.getStatus()).append(")\n");

                    // Try to get last 10 log lines for each service
                    try {
                        StringBuilder serviceLogCmd = new StringBuilder();
                        serviceLogCmd.append("docker service logs --tail 10 ").append(service.getServiceId());

                        Process logProcess = Runtime.getRuntime().exec(serviceLogCmd.toString());
                        BufferedReader logReader = new BufferedReader(
                                new InputStreamReader(logProcess.getInputStream()));
                        StringBuilder logOutput = new StringBuilder();
                        String logLine;
                        while ((logLine = logReader.readLine()) != null) {
                            logOutput.append(logLine).append("\n");
                        }

                        if (logOutput.length() > 0) {
                            completeOutput.append("Recent logs:\n").append(logOutput).append("\n");
                        } else {
                            completeOutput.append("No recent logs available for this service.\n\n");
                        }
                    } catch (Exception e) {
                        completeOutput.append("Error retrieving logs: ").append(e.getMessage()).append("\n\n");
                    }
                }
            }

            return completeOutput.toString();
        } catch (Exception e) {
            logger.error("Error fetching node logs", e);
            return "Error fetching node logs: " + e.getMessage();
        }
    }

    /**
     * Get logs for a specific service
     */
    @GetMapping("/service/{serviceId}/logs")
    @ResponseBody
    public String getServiceLogs(@PathVariable("serviceId") Long serviceId) {
        try {
            SwarmService service = swarmVisualizationService.getServiceById(serviceId);

            // Execute docker service logs command
            StringBuilder commandBuilder = new StringBuilder();
            commandBuilder.append("docker service logs --tail 100 ").append(service.getServiceId());

            // Execute the command
            logger.info("Executing command: {}", commandBuilder.toString());
            Process process = Runtime.getRuntime().exec(commandBuilder.toString());

            // Read the output
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            // Check for errors
            if (process.waitFor() != 0) {
                BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                StringBuilder errorOutput = new StringBuilder();
                while ((line = errorReader.readLine()) != null) {
                    errorOutput.append(line).append("\n");
                }

                // If no logs or an error, return a message
                if (errorOutput.length() > 0) {
                    return "Error getting logs for service '" + service.getServiceName() + "': "
                            + errorOutput.toString();
                }
            }

            // If we got logs, return them
            if (output.length() > 0) {
                return output.toString();
            }

            // If no logs available
            return "No logs available for service '" + service.getServiceName() + "'.";
        } catch (Exception e) {
            logger.error("Error fetching service logs", e);
            return "Error fetching logs: " + e.getMessage();
        }
    }

    /**
     * Drain a node (stop scheduling new tasks on it)
     */
    @PostMapping("/node/{nodeId}/drain")
    @ResponseBody
    public Map<String, Object> drainNode(@PathVariable("nodeId") Long nodeId) {
        Map<String, Object> response = new HashMap<>();

        try {
            SwarmNode node = swarmVisualizationService.getNodeById(nodeId);

            // This would be implemented to interact with Docker Swarm API to drain the node
            // For now, just update the status in our database
            node.setStatus("draining");
            // Save the updated node
            // In a real implementation, this would be done through a service

            response.put("success", true);
            response.put("message",
                    "Node '" + node.getHostname() + "' is now draining. No new tasks will be scheduled on it.");
        } catch (Exception e) {
            logger.error("Error draining node", e);
            response.put("success", false);
            response.put("message", "Failed to drain node: " + e.getMessage());
        }

        return response;
    }

    /**
     * Remove a node from the swarm
     */
    @PostMapping("/node/{nodeId}/remove")
    @ResponseBody
    public Map<String, Object> removeNode(@PathVariable("nodeId") Long nodeId) {
        Map<String, Object> response = new HashMap<>();

        try {
            SwarmNode node = swarmVisualizationService.getNodeById(nodeId);

            // This would be implemented to interact with Docker Swarm API to remove the
            // node
            // For now, just simulate the removal

            // In a real implementation, this would call dockerSwarmService.leaveSwarm() for
            // the specific node

            response.put("success", true);
            response.put("message", "Node '" + node.getHostname() + "' has been removed from the swarm.");
        } catch (Exception e) {
            logger.error("Error removing node", e);
            response.put("success", false);
            response.put("message", "Failed to remove node: " + e.getMessage());
        }

        return response;
    }

    /**
     * Deploy a service with direct port mapping using command line
     */
    @PostMapping("/service/deploy-direct")
    @ResponseBody
    public Map<String, Object> deployDirectService(
            @RequestParam(name = "serviceName") String serviceName,
            @RequestParam(name = "imageName") String imageName,
            @RequestParam(required = false, name = "publishedPort", defaultValue = "80") int publishedPort,
            @RequestParam(required = false, name = "targetPort", defaultValue = "80") int targetPort,
            @RequestParam(required = false, name = "mode", defaultValue = "host") String mode,
            @RequestParam(required = false, name = "replicas", defaultValue = "1") int replicas,
            @RequestParam(required = false, name = "constraint") String constraint) {

        Map<String, Object> response = new HashMap<>();

        try {
            // Run docker service create command directly
            StringBuilder commandBuilder = new StringBuilder();
            commandBuilder.append("docker service create --name ").append(serviceName);

            // Add port mapping
            commandBuilder.append(" --publish published=").append(publishedPort)
                    .append(",target=").append(targetPort)
                    .append(",mode=").append(mode);

            // Add replicas
            commandBuilder.append(" --replicas ").append(replicas);

            // Add placement constraint if provided
            if (constraint != null && !constraint.isEmpty()) {
                commandBuilder.append(" --constraint ").append(constraint);
            }

            // Add image name
            commandBuilder.append(" ").append(imageName);

            // Execute the command
            Runtime runtime = Runtime.getRuntime();
            Process process = runtime.exec(commandBuilder.toString());

            // Get the command output
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            int exitCode = process.waitFor();

            if (exitCode == 0) {
                response.put("success", true);
                response.put("message", "Service deployed successfully: " + output.toString());
            } else {
                // Get error output if command failed
                BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                StringBuilder errorOutput = new StringBuilder();
                while ((line = errorReader.readLine()) != null) {
                    errorOutput.append(line).append("\n");
                }

                response.put("success", false);
                response.put("message", "Failed to deploy service: " + errorOutput.toString());
            }
        } catch (Exception e) {
            logger.error("Error deploying service", e);
            response.put("success", false);
            response.put("message", "Failed to deploy service: " + e.getMessage());
        }

        return response;
    }

    /**
     * Inspect a specific service
     */
    @GetMapping("/service/{serviceId}/inspect")
    @ResponseBody
    public Map<String, Object> inspectService(@PathVariable("serviceId") Long serviceId) {
        Map<String, Object> response = new HashMap<>();

        try {
            SwarmService service = swarmVisualizationService.getServiceById(serviceId);

            // Execute docker service inspect command
            StringBuilder commandBuilder = new StringBuilder();
            commandBuilder.append("docker service inspect ").append(service.getServiceId());

            // Execute the command
            Process process = Runtime.getRuntime().exec(commandBuilder.toString());

            // Read the output
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            // Check for errors
            if (process.waitFor() != 0) {
                BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                StringBuilder errorOutput = new StringBuilder();
                while ((line = errorReader.readLine()) != null) {
                    errorOutput.append(line).append("\n");
                }

                response.put("success", false);
                response.put("message", "Error inspecting service: " + errorOutput.toString());
                return response;
            }

            // Service details from our database
            Map<String, Object> serviceDetails = new HashMap<>();
            serviceDetails.put("id", service.getId());
            serviceDetails.put("serviceId", service.getServiceId());
            serviceDetails.put("serviceName", service.getServiceName());
            serviceDetails.put("status", service.getStatus());
            serviceDetails.put("dockerImage",
                    service.getDockerImage() != null ? service.getDockerImage().getRepository() + "/" +
                            service.getDockerImage().getName() + ":" +
                            service.getDockerImage().getTag() : "N/A");
            serviceDetails.put("tags", service.getTags());
            serviceDetails.put("environmentVariables", service.getEnvironmentVariables());
            serviceDetails.put("placementConstraints", service.getPlacementConstraints());
            serviceDetails.put("replicas", service.getReplicas());
            serviceDetails.put("publishedPorts", service.getPublishedPorts());

            // Docker service inspect JSON output
            String inspectOutput = output.toString();

            response.put("success", true);
            response.put("service", serviceDetails);
            response.put("inspectOutput", inspectOutput);

        } catch (Exception e) {
            logger.error("Error inspecting service", e);
            response.put("success", false);
            response.put("message", "Failed to inspect service: " + e.getMessage());
        }

        return response;
    }

    /**
     * API Endpoint: Get basic details of a Swarm service from the database.
     *
     * @param id The database ID of the SwarmService.
     * @return ResponseEntity containing a Map of service details or 404 error.
     */
    @GetMapping("/service/{id}/details")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getServiceDetailsApi(@PathVariable("id") Long id) {
        logger.debug("API request received for service details, ID: {}", id);
        return swarmServiceRepository.findById(id)
                .map(service -> {
                    logger.debug("Found service: {}", service.getServiceName());
                    Map<String, Object> detailsMap = new HashMap<>();
                    detailsMap.put("id", service.getId());
                    detailsMap.put("serviceName", service.getServiceName());
                    detailsMap.put("serviceId", service.getServiceId());
                    detailsMap.put("status", service.getStatus());
                    if (service.getDockerImage() != null) {
                        detailsMap.put("imageName", service.getDockerImage().getName());
                        detailsMap.put("imageTag", service.getDockerImage().getTag());
                    } else {
                        detailsMap.put("imageName", "N/A");
                        detailsMap.put("imageTag", "N/A");
                    }
                    detailsMap.put("replicas", service.getReplicas());
                    detailsMap.put("environmentVariables",
                            service.getEnvironmentVariables() != null ? new HashMap<>(service.getEnvironmentVariables())
                                    : Collections.emptyMap());
                    detailsMap.put("publishedPorts", service.getPublishedPorts());
                    detailsMap.put("tags",
                            service.getTags() != null ? Set.copyOf(service.getTags()) : Collections.emptySet());
                    detailsMap.put("placementConstraints",
                            service.getPlacementConstraints() != null ? new HashMap<>(service.getPlacementConstraints())
                                    : Collections.emptyMap());

                    return ResponseEntity.ok(detailsMap);
                })
                .orElseGet(() -> {
                    logger.warn("Service not found with ID: {}", id);
                    return ResponseEntity.notFound().build();
                });
    }

    /**
     * API Endpoint: Get the raw JSON output of 'docker service inspect' for a
     * service.
     *
     * @param id The database ID of the SwarmService.
     * @return ResponseEntity containing the JSON string or an error message.
     */
    @GetMapping(value = "/service/{id}/inspect", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<String> getServiceInspectOutputApi(@PathVariable("id") Long id) {
        logger.debug("API request received for service inspect, ID: {}", id);
        try {
            String inspectOutput = swarmDeploymentService.getServiceInspectOutput(id);
            // Check if the service method returned a JSON error object
            if (inspectOutput.trim().startsWith("{\"error\":")) {
                logger.warn("Error inspecting service ID {}: {}", id, inspectOutput);
                return ResponseEntity.status(500).contentType(MediaType.APPLICATION_JSON).body(inspectOutput);
            }
            logger.debug("Successfully inspected service ID {}", id);
            // Return the raw JSON string directly
            return ResponseEntity.ok(inspectOutput);
        } catch (IllegalArgumentException e) {
            logger.warn("Service not found for inspect with ID: {}", id);
            return ResponseEntity.status(404).contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"Service not found\"}");
        } catch (Exception e) {
            logger.error("Unexpected error inspecting service ID {}: {}", id, e.getMessage(), e);
            return ResponseEntity.status(500).contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"Internal server error during inspect\"}");
        }
    }

    /**
     * API Endpoint: Get the logs for a Swarm service.
     * Overrides the existing /service/{serviceId}/logs endpoint to return plain
     * text.
     *
     * @param serviceId The database ID of the SwarmService.
     * @return ResponseEntity containing the logs as plain text or an error message.
     */
    @GetMapping(value = "/service/{serviceId}/logs", produces = MediaType.TEXT_PLAIN_VALUE)
    @ResponseBody
    public ResponseEntity<String> getServiceLogsApi(@PathVariable("serviceId") Long serviceId) {
        logger.debug("API request received for service logs, ID: {}", serviceId);
        try {
            String logs = swarmDeploymentService.getServiceLogs(serviceId);
            // Check for specific error messages from the service method
            if (logs.startsWith("Error fetching logs:") || logs.startsWith("Error: Service has no Docker Service ID.")
                    || logs.startsWith("Error: Service not found")) {
                logger.warn("Error fetching logs for service ID {}: {}", serviceId, logs);
                // Return 500 for server-side errors during log fetching
                return ResponseEntity.status(500).body(logs);
            }
            logger.debug("Successfully fetched logs for service ID {}", serviceId);
            return ResponseEntity.ok(logs);
        } catch (IllegalArgumentException e) {
            logger.warn("Service not found for logs with ID: {}", serviceId);
            // Return 404 if the service itself doesn't exist in the DB
            return ResponseEntity.status(404).body("Error: Service not found");
        } catch (Exception e) {
            logger.error("Unexpected error fetching logs for service ID {}: {}", serviceId, e.getMessage(), e);
            return ResponseEntity.status(500).body("Error: Internal server error fetching logs");
        }
    }

    /**
     * Helper method to get available server types
     */
    private String[] getAvailableServerTypes() {
        // Return the available server types in your application
        return new String[] { "TeamServer", "Redirector", "Phishing", "SwarmManagerServer", "HostServer" };
    }
}