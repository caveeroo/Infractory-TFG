package com.tfg.infractory.web.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.tfg.infractory.domain.model.Server;
import com.tfg.infractory.domain.service.InfrastructureService;
import com.tfg.infractory.domain.service.InstanceService;
import com.tfg.infractory.infrastructure.nebula.service.NebulaService;
import com.tfg.infractory.infrastructure.secrets.service.SecretsService;

@Controller
@RequestMapping("/")
public class DashboardController {

    private final InfrastructureService infrastructureService;
    private final InstanceService instanceService;
    private final NebulaService nebulaService;
    private final SecretsService secretsService;

    @Autowired
    public DashboardController(InfrastructureService infrastructureService,
            InstanceService instanceService,
            NebulaService nebulaService,
            SecretsService secretsService) {
        this.infrastructureService = infrastructureService;
        this.instanceService = instanceService;
        this.nebulaService = nebulaService;
        this.secretsService = secretsService;
    }

    @GetMapping
    public String viewDashboard(Model model) {
        // Get active servers count
        long activeServers = infrastructureService.getAllServers().stream()
                .filter(Server::getOnline)
                .count();
        model.addAttribute("activeServers", activeServers);

        // Get active instances count
        long activeInstances = instanceService.getAllInstances().stream()
                .filter(instance -> instance.getDestroyed() == null)
                .count();
        model.addAttribute("activeInstances", activeInstances);

        // Get Nebula configs count
        long nebulaConfigs = nebulaService.getAllNebulaConfigs().size();
        model.addAttribute("nebulaConfigs", nebulaConfigs); // Added for consistency with HiController

        // Get stored secrets count
        long storedSecrets = secretsService.getAllSecrets().size();
        model.addAttribute("storedSecrets", storedSecrets); // Added for consistency with HiController

        // Get total instances count
        long totalInstances = instanceService.getAllInstances().size();
        model.addAttribute("totalInstances", totalInstances); // Added from HiController

        return "dashboard/index";
    }
}