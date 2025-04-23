package com.tfg.infractory.web.controller;

import com.tfg.infractory.domain.model.Instance;
import com.tfg.infractory.domain.model.Phishing;
import com.tfg.infractory.domain.model.Redirector;
import com.tfg.infractory.domain.model.Server;
import com.tfg.infractory.domain.model.TeamServer;
import com.tfg.infractory.domain.service.InfrastructureService;
import com.tfg.infractory.domain.service.InstanceService;
import com.tfg.infractory.infrastructure.ssh.model.SSHKey;
import com.tfg.infractory.infrastructure.ssh.service.SSHKeyService;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;
import com.tfg.infractory.infrastructure.nebula.service.NebulaConfigService;
import com.tfg.infractory.infrastructure.cloud.service.CloudProviderService;
import com.tfg.infractory.web.event.ServerCreatedEvent;
import com.tfg.infractory.infrastructure.host.service.HostServerService;
import com.tfg.infractory.domain.model.HostServer;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.Setter;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller
@RequestMapping("/infrastructure")
public class InfrastructureController {

    private static final Logger logger = LoggerFactory.getLogger(InfrastructureController.class);

    private final InfrastructureService infraService;
    private final InstanceService instanceService;
    private final SSHKeyService sshKeyService;
    private final NebulaConfigService nebulaConfigService;
    private final Map<String, CloudProviderService> cloudProviderServices;
    private final ApplicationEventPublisher eventPublisher;
    private final HostServerService hostServerService;

    public InfrastructureController(InfrastructureService infraService, InstanceService instanceService,
            SSHKeyService sshKeyService, NebulaConfigService nebulaConfigService,
            Map<String, CloudProviderService> cloudProviderServices,
            ApplicationEventPublisher eventPublisher, HostServerService hostServerService) {
        this.infraService = infraService;
        this.instanceService = instanceService;
        this.sshKeyService = sshKeyService;
        this.nebulaConfigService = nebulaConfigService;
        this.cloudProviderServices = cloudProviderServices;
        this.eventPublisher = eventPublisher;
        this.hostServerService = hostServerService;
    }

    @ModelAttribute("contextPath")
    public String contextPath(final HttpServletRequest request) {
        return request.getContextPath();
    }

    @Getter
    @Setter
    public static class Column {
        private String title;
        private List<Server> components;

        public Column(String title, List<Server> components) {
            this.title = title;
            this.components = components;
        }
    }

    @GetMapping
    public String viewInfrastructure(Model model) {
        List<Server> allServers = infraService.getAllServers();

        // Update instance statuses
        for (Server server : allServers) {
            if (server.getInstance() != null) {
                Instance instance = server.getInstance();
                try {
                    CloudProviderService cloudProviderService = cloudProviderServices
                            .get(instance.getProvider().getName());
                    if (cloudProviderService != null) {
                        Instance.InstanceStatus status = cloudProviderService
                                .getInstanceStatus(instance.getProviderId());
                        instance.setStatus(status);
                        instanceService.updateInstance(instance.getId(), instance);
                    }
                } catch (Exception e) {
                    logger.error("Error updating instance status: {}", e.getMessage());
                }
            }
        }

        List<Server> phishingComponents = allServers.stream()
                .filter(s -> s instanceof Phishing || (s instanceof Redirector
                        && ((Redirector) s).getDetails().getDescription().equals("SMTP Relay")))
                .sorted((c1, c2) -> c2.getDetails().getName().compareTo(c1.getDetails().getName()))
                .toList();

        List<Server> teamserverComponents = allServers.stream()
                .filter(s -> s instanceof TeamServer || (s instanceof Redirector
                        && ((Redirector) s).getDetails().getDescription().contains("Redirector")))
                .sorted((c1, c2) -> c2.getDetails().getName().compareTo(c1.getDetails().getName()))
                .toList();

        List<Server> otherComponents = allServers.stream()
                .filter(s -> !(phishingComponents.contains(s) || teamserverComponents.contains(s)))
                .sorted((c1, c2) -> c2.getDetails().getName().compareTo(c1.getDetails().getName()))
                .toList();

        Column phishingColumn = new Column("Phishing", phishingComponents);
        Column teamserverColumn = new Column("TeamServer", teamserverComponents);
        Column otherColumn = new Column("Other", otherComponents);

        model.addAttribute("columns", List.of(phishingColumn, teamserverColumn, otherColumn));
        return "infrastructure/index";
    }

    @GetMapping("/edit")
    public String editInfrastructure(Model model) {
        List<Server> servers = infraService.getAllServers();
        List<Instance> availableInstances = instanceService.getAllInstances();
        model.addAttribute("servers", servers);
        model.addAttribute("availableInstances", availableInstances);
        return "infrastructure/edit";
    }

    @PostMapping("/update")
    public String updateInfrastructure(@RequestParam Map<String, String> params) {
        logger.info("Updating infrastructure with params: {}", params);
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (entry.getKey().startsWith("server_")) {
                Long serverId = Long.parseLong(entry.getKey().substring(7));
                Long instanceId = Long.parseLong(entry.getValue());
                logger.info("Assigning instance {} to server {}", instanceId, serverId);
                infraService.assignInstanceToServer(serverId, instanceId);
            }
        }
        return "redirect:/infrastructure";
    }

    /**
     * Display the form for creating new infrastructure.
     * This method filters out instances and Nebula configurations that are already
     * in use
     * by existing servers to prevent potential conflicts during infrastructure
     * creation.
     * Resources that are already assigned to servers will not appear in the
     * selection dropdowns.
     *
     * @param model The Spring model to add attributes to
     * @return The name of the view to render
     */
    @GetMapping("/create")
    public String createInfrastructureForm(Model model) {
        // Get all resources
        List<Instance> allInstances = instanceService.getAllInstances();
        List<SSHKey> availableSSHKeys = sshKeyService.getAllSSHKeys();
        List<Nebula> allNebulaConfigs = nebulaConfigService.getAllNebulaConfigs();

        // Get all servers to check for used resources
        List<Server> existingServers = infraService.getAllServers();

        // Filter out instances that are already in use
        Set<Instance> usedInstances = existingServers.stream()
                .map(Server::getInstance)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        List<Instance> availableInstances = allInstances.stream()
                .filter(instance -> !usedInstances.contains(instance))
                .collect(Collectors.toList());

        // Filter out Nebula configs that are already in use by regular servers
        Set<Nebula> usedNebulaConfigs = existingServers.stream()
                .map(Server::getVpn)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        // Also filter out Nebula configs used by the host server
        HostServer hostServer = hostServerService.findHostServer();
        if (hostServer != null && hostServer.getVpn() != null) {
            usedNebulaConfigs.add(hostServer.getVpn());
        }

        List<Nebula> availableNebulaConfigs = allNebulaConfigs.stream()
                .filter(nebula -> !usedNebulaConfigs.contains(nebula))
                .collect(Collectors.toList());

        model.addAttribute("availableInstances", availableInstances);
        model.addAttribute("availableSSHKeys", availableSSHKeys);
        model.addAttribute("availableNebulaConfigs", availableNebulaConfigs);

        return "infrastructure/create";
    }

    @PostMapping("/create")
    public String createInfrastructure(@RequestParam Map<String, String> params) {
        try {
            String serverType = params.get("serverType");
            Long instanceId = Long.parseLong(params.get("instanceId"));
            String description = params.get("description");
            Long sshKeyId = Long.parseLong(params.get("sshKeyId"));
            Long nebulaConfigId = Long.parseLong(params.get("nebulaConfigId"));

            Nebula nebulaConfig = nebulaConfigService.getNebulaConfigById(nebulaConfigId);

            // Create server with all necessary configurations
            // Docker configurations are not set during creation and will be managed with
            // Swarm later
            Server server = infraService.createServer(serverType, instanceId, description, sshKeyId, nebulaConfig,
                    null);

            // Publish single event to handle both Nebula deployment and Swarm setup
            eventPublisher.publishEvent(new ServerCreatedEvent(this, server));

            return "redirect:/infrastructure";
        } catch (Exception e) {
            logger.error("Failed to create infrastructure", e);
            return "redirect:/infrastructure/create?error=" + e.getMessage();
        }
    }

    @GetMapping("/servers/edit")
    public String editServers(Model model) {
        List<Server> servers = infraService.getAllServers();

        // Get all instances
        List<Instance> allInstances = instanceService.getAllInstances();

        // Show all instances in the edit form - each server can keep its current
        // instance
        // or we can allow reassignment even if that creates temporary conflicts
        // (they'll be resolved when the form is submitted)

        model.addAttribute("servers", servers);
        model.addAttribute("availableInstances", allInstances);
        return "infrastructure/servers/edit";
    }

    @PostMapping("/servers/update")
    public String updateServers(@RequestParam Map<String, String> params) {
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (entry.getKey().startsWith("server_") && !entry.getKey().endsWith("_description")) {
                Long serverId = Long.parseLong(entry.getKey().substring(7));
                Long instanceId = Long.parseLong(entry.getValue());
                String description = params.get("server_" + serverId + "_description");
                infraService.updateServerInstanceAndDescription(serverId, instanceId, description);
            }
        }
        return "redirect:/infrastructure";
    }
}