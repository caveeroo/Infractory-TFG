package com.tfg.infractory.web.controller;

import com.tfg.infractory.domain.model.DockerImage;
import com.tfg.infractory.domain.model.DockerConfig;
import com.tfg.infractory.domain.model.ConfigAssignment;
import com.tfg.infractory.domain.model.Instance;
import com.tfg.infractory.domain.model.Server;
import com.tfg.infractory.domain.service.DockerImageService;
import com.tfg.infractory.domain.service.DockerConfigService;
import com.tfg.infractory.domain.service.ConfigAssignmentService;
import com.tfg.infractory.domain.service.InstanceService;
import com.tfg.infractory.domain.repository.ServerRepository;
import com.tfg.infractory.infrastructure.docker.service.DockerService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.util.List;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/docker")
public class DockerController {

    @Autowired
    private DockerImageService dockerImageService;

    @Autowired
    private DockerConfigService dockerConfigService;

    @Autowired
    private ConfigAssignmentService configAssignmentService;

    @Autowired
    private InstanceService instanceService;

    @Autowired
    private DockerService dockerService;

    @Autowired
    private ServerRepository serverRepository;

    @GetMapping("/images")
    public String viewDockerImages(Model model) {
        List<DockerImage> dockerImages = dockerImageService.getAllDockerImages();
        model.addAttribute("dockerImages", dockerImages);
        return "docker/images";
    }

    @GetMapping("/configs")
    public String viewDockerConfigs(Model model) {
        List<DockerConfig> dockerConfigs = dockerConfigService.getAllDockerConfigs();
        model.addAttribute("dockerConfigs", dockerConfigs);
        return "docker/configs";
    }

    @PostMapping("/images/create")
    public String createDockerImage(@ModelAttribute DockerImage dockerImage) {
        dockerImageService.createDockerImage(dockerImage);
        return "redirect:/docker/images";
    }

    @PostMapping("/configs/create")
    public String createDockerConfig(@ModelAttribute DockerConfig dockerConfig) {
        dockerConfigService.createDockerConfig(dockerConfig);
        return "redirect:/docker/configs";
    }

    /**
     * View assignments for a specific Docker configuration
     */
    @GetMapping("/configs/{configId}/assignments")
    public String viewConfigAssignments(@PathVariable Long configId, Model model) {
        DockerConfig config = dockerConfigService.getDockerConfigById(configId);
        List<ConfigAssignment> assignments = configAssignmentService.getAssignmentsForConfig(config);

        model.addAttribute("config", config);
        model.addAttribute("assignments", assignments);
        model.addAttribute("serverTypes", getAvailableServerTypes());
        model.addAttribute("instances", instanceService.getAllInstances());

        return "docker/assignments";
    }

    /**
     * Assign a Docker configuration to a server type
     */
    @PostMapping("/configs/{configId}/assign-to-type")
    public String assignToServerType(
            @PathVariable Long configId,
            @RequestParam String serverType) {

        DockerConfig config = dockerConfigService.getDockerConfigById(configId);
        configAssignmentService.assignToServerType(config, serverType);

        return "redirect:/docker/configs/" + configId + "/assignments";
    }

    /**
     * Assign a Docker configuration to a specific instance
     */
    @PostMapping("/configs/{configId}/assign-to-instance")
    public String assignToInstance(
            @PathVariable Long configId,
            @RequestParam Long instanceId) {

        DockerConfig config = dockerConfigService.getDockerConfigById(configId);
        Instance instance = instanceService.getInstance(instanceId);
        configAssignmentService.assignToInstance(config, instance);

        return "redirect:/docker/configs/" + configId + "/assignments";
    }

    /**
     * Delete a config assignment
     */
    @PostMapping("/assignments/{assignmentId}/delete")
    public String deleteAssignment(
            @PathVariable Long assignmentId,
            @RequestParam Long configId) {

        configAssignmentService.deleteAssignment(assignmentId);
        return "redirect:/docker/configs/" + configId + "/assignments";
    }

    /**
     * Apply Docker configurations to an instance
     */
    @PostMapping("/instances/{instanceId}/apply-configs")
    @ResponseBody
    public Map<String, String> applyConfigsToInstance(@PathVariable Long instanceId) {
        Map<String, String> response = new HashMap<>();

        try {
            Instance instance = instanceService.getInstance(instanceId);
            Server server = serverRepository.findByInstance(instance);
            if (server != null) {
                dockerService.applyDockerConfigs(server);
                response.put("status", "success");
                response.put("message", "Docker configurations applied successfully");
            } else {
                response.put("status", "error");
                response.put("message", "No server associated with this instance");
            }
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "Error applying Docker configurations: " + e.getMessage());
        }

        return response;
    }

    /**
     * Helper method to get available server types
     */
    private String[] getAvailableServerTypes() {
        // Return the available server types in your application
        return new String[] { "TeamServer", "HostServer", "Redirector", "SwarmManagerServer" };
    }

    // Add other methods for updating and deleting Docker images and configs as
    // needed
}