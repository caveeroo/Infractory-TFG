package com.tfg.infractory.web.controller;

import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.validation.Valid;
import org.springframework.ui.Model;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import com.tfg.infractory.web.dto.NebulaConfigurationDTO;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.propertyeditors.StringTrimmerEditor;
import com.tfg.infractory.infrastructure.nebula.service.NebulaService;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import com.tfg.infractory.infrastructure.nebula.service.NebulaDeploymentService;
import com.tfg.infractory.infrastructure.nebula.service.NebulaCertificateService;

@Controller
@RequestMapping("/nebula")
public class NebulaController {

    private static final Logger logger = LoggerFactory.getLogger(NebulaController.class);

    @Autowired
    private NebulaService nebulaService;

    @Autowired
    private NebulaCertificateService nebulaCertificateService;

    @Autowired
    private NebulaDeploymentService nebulaDeploymentService;

    @InitBinder
    public void initBinder(WebDataBinder binder) {
        // Trim strings and convert empty strings to null
        binder.registerCustomEditor(String.class, new StringTrimmerEditor(true));

        // Add custom conversion for string to Set<String> fields
        // These editors will convert comma-separated strings from the form inputs to
        // Set<String>
        binder.registerCustomEditor(Set.class, "roles", new StringToSetPropertyEditor());
        binder.registerCustomEditor(Set.class, "allowedRoles", new StringToSetPropertyEditor());
        binder.registerCustomEditor(Set.class, "allowedCIDRs", new StringToSetPropertyEditor());
        binder.registerCustomEditor(Set.class, "lighthouseIps", new StringToSetPropertyEditor());
    }

    @GetMapping
    public String viewNebulaConfigs(Model model) {
        // Force a refresh of the Nebula configurations
        List<Nebula> nebulaConfigs = nebulaService.refreshAndGetAllNebulaConfigs();

        // Calculate total unique roles
        Set<String> uniqueRoles = nebulaConfigs.stream()
                .flatMap(config -> config.getRoles().stream())
                .collect(Collectors.toSet());

        model.addAttribute("nebulaConfigs", nebulaConfigs);
        model.addAttribute("totalUniqueRoles", uniqueRoles.size());
        return "nebula/index";
    }

    @GetMapping("/create")
    public String createNebulaConfigForm(Model model) {
        model.addAttribute("nebulaConfig", new NebulaConfigurationDTO());
        List<Nebula> lighthouses = nebulaService.getAllLighthouseConfigs();
        model.addAttribute("lighthouses", lighthouses);
        return "nebula/create";
    }

    @PostMapping("/create")
    public String createNebulaConfig(Model model,
            @Valid @ModelAttribute("nebulaConfig") NebulaConfigurationDTO nebulaConfig,
            BindingResult bindingResult,
            @RequestParam(name = "rolesString", required = false) String rolesString,
            @RequestParam(name = "allowedRolesString", required = false) String allowedRolesString,
            @RequestParam(name = "allowedCIDRsString", required = false) String allowedCIDRsString,
            @RequestParam(name = "lighthouseIpsString", required = false) String lighthouseIpsString,
            RedirectAttributes redirectAttributes) {
        if (bindingResult.hasErrors()) {
            List<Nebula> lighthouses = nebulaService.getAllLighthouseConfigs();
            model.addAttribute("lighthouses", lighthouses);
            return "nebula/create";
        }

        try {
            if (nebulaConfig.getRoles() == null && rolesString != null && !rolesString.isEmpty()) {
                nebulaConfig.setRoles(Arrays.stream(rolesString.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet()));
            } else if (nebulaConfig.getRoles() == null) {
                nebulaConfig.setRoles(new HashSet<>());
            }

            if (nebulaConfig.getAllowedRoles() == null && allowedRolesString != null && !allowedRolesString.isEmpty()) {
                nebulaConfig.setAllowedRoles(Arrays.stream(allowedRolesString.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet()));
            } else if (nebulaConfig.getAllowedRoles() == null) {
                nebulaConfig.setAllowedRoles(new HashSet<>());
            }

            if (nebulaConfig.getAllowedCIDRs() == null && allowedCIDRsString != null && !allowedCIDRsString.isEmpty()) {
                nebulaConfig.setAllowedCIDRs(Arrays.stream(allowedCIDRsString.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet()));
            } else if (nebulaConfig.getAllowedCIDRs() == null) {
                nebulaConfig.setAllowedCIDRs(new HashSet<>());
            }

            if (nebulaConfig.getLighthouseIps() == null && lighthouseIpsString != null
                    && !lighthouseIpsString.isEmpty()) {
                nebulaConfig.setLighthouseIps(Arrays.stream(lighthouseIpsString.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet()));
            } else if (nebulaConfig.getLighthouseIps() == null && !nebulaConfig.getLighthouse()) {
                nebulaConfig.setLighthouseIps(new HashSet<>());
            }

            Nebula createdNebula = nebulaService.createNebulaConfig(nebulaConfig);
            nebulaCertificateService.generateAndSaveCA();

            nebulaService.refreshNebulaConfigsCache();

            redirectAttributes.addFlashAttribute("successMessage",
                    "Nebula configuration created successfully with ID: " + createdNebula.getId());
        } catch (RuntimeException e) {
            logger.error("Error creating Nebula configuration", e);
            redirectAttributes.addFlashAttribute("errorMessage",
                    "Failed to create Nebula configuration: " + e.getMessage());
            model.addAttribute("lighthouses", nebulaService.getAllLighthouseConfigs());
            return "nebula/create";
        }
        return "redirect:/nebula";
    }

    // Custom property editor to convert comma-separated strings to Set<String>
    private static class StringToSetPropertyEditor extends java.beans.PropertyEditorSupport {
        @Override
        public void setAsText(String text) {
            if (text == null || text.isEmpty()) {
                setValue(new HashSet<>());
            } else {
                Set<String> result = Arrays.stream(text.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet());
                setValue(result);
            }
        }
    }

    @PostMapping("/{id}/delete")
    public String deleteNebulaConfig(@PathVariable Long id, RedirectAttributes redirectAttributes) {
        try {
            nebulaService.deleteNebulaConfig(id);
            redirectAttributes.addFlashAttribute("successMessage", "Nebula configuration deleted successfully");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage",
                    "Failed to delete Nebula configuration: " + e.getMessage());
        }
        return "redirect:/nebula";
    }

    @PostMapping("/deploy/{instanceId}")
    public String deployNebula(@PathVariable Long instanceId, @RequestParam Long nebulaConfigId,
            RedirectAttributes redirectAttributes) {
        try {
            Nebula nebulaConfig = nebulaService.getNebulaConfigById(nebulaConfigId);
            // Instance instance = instanceService.getInstance(instanceId);

            // Deploy Nebula
            nebulaDeploymentService.deployNebulaToInstance(instanceId, nebulaConfig.getId());

            // Ensure Docker is installed and instance is part of the Swarm
            // SSHKey sshKey = instance.getSshKey();
            // String swarmResult =
            // dockerSwarmService.initializeDockerAndJoinSwarm(instance, sshKey);
            // logger.info("Docker Swarm initialization result for instance {}: {}",
            // instanceId, swarmResult);

            redirectAttributes.addFlashAttribute("successMessage",
                    "Nebula deployed successfully to instance: " + instanceId + " and joined Docker Swarm");
        } catch (RuntimeException e) {
            logger.error("Error deploying Nebula to instance: {}", instanceId, e);
            redirectAttributes.addFlashAttribute("errorMessage", "Failed to deploy Nebula: " + e.getMessage());
        }
        return "redirect:/nebula";
    }
}