package com.tfg.infractory.web.controller;

import java.util.List;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tfg.infractory.domain.model.Instance;
import com.tfg.infractory.domain.service.InstanceService;
import com.tfg.infractory.infrastructure.cloud.model.Image;
import com.tfg.infractory.infrastructure.cloud.model.Region;
import com.tfg.infractory.infrastructure.cloud.model.Size;
import com.tfg.infractory.infrastructure.cloud.service.CloudProviderService;
import com.tfg.infractory.infrastructure.ssh.model.SSHKey;
import com.tfg.infractory.infrastructure.ssh.service.SSHKeyService;

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller
@RequestMapping("/instances")
public class InstanceController {

    private final Map<String, CloudProviderService> cloudProviderServices;

    private static final Logger logger = LoggerFactory.getLogger(InstanceController.class);

    @Autowired
    private InstanceService instanceService;

    @Autowired
    private SSHKeyService sshKeyService;

    @Autowired
    public InstanceController(List<CloudProviderService> cloudProviderServices) {
        this.cloudProviderServices = cloudProviderServices.stream()
                .collect(Collectors.toMap(
                        service -> {
                            String simpleName = service.getClass().getSimpleName();
                            return simpleName.equals("LocalProviderService") ? "Local"
                                    : simpleName.replace("CloudProviderService", "").replace("ProviderService", "");
                        },
                        Function.identity()));
        logger.info("Initialized cloud provider services: {}", this.cloudProviderServices.keySet());
    }

    @GetMapping("/create")
    public String createInstanceForm(Model model) {
        for (Map.Entry<String, CloudProviderService> entry : cloudProviderServices.entrySet()) {
            String providerName = entry.getKey();
            CloudProviderService service = entry.getValue();

            logger.info("Processing provider: {}", providerName);

            if (service != null) {
                List<Region> regions = service.getAvailableRegions();
                List<Size> sizes = service.getAvailableSizes();
                List<Image> images = service.getAllImages();
                logger.info("{} Regions: {}", providerName, regions.size());
                logger.info("{} Sizes: {}", providerName, sizes.size());
                logger.info("{} Images: {}", providerName, images.size());
                model.addAttribute(providerName.toLowerCase() + "Regions", regions);
                model.addAttribute(providerName.toLowerCase() + "Sizes", sizes);
                model.addAttribute(providerName.toLowerCase() + "Images", images);
            } else {
                logger.warn("{} service is null", providerName);
                model.addAttribute(providerName.toLowerCase() + "Regions", List.of());
                model.addAttribute(providerName.toLowerCase() + "Sizes", List.of());
                model.addAttribute(providerName.toLowerCase() + "Images", List.of());
            }
        }

        model.addAttribute("providers", cloudProviderServices.keySet());
        model.addAttribute("sshKeys", sshKeyService.getAllSSHKeys());

        // Log all attributes added to the model
        logger.info("Model attributes: {}", model.asMap().keySet());

        return "instances/create";
    }

    @PostMapping("/create")
    public String createInstance(@RequestParam Map<String, String> params, Model model,
            RedirectAttributes redirectAttributes) {
        try {
            String provider = params.get("provider");
            logger.info("Creating instance for provider: {}", provider);
            logger.info("Available providers: {}", cloudProviderServices.keySet());

            CloudProviderService service = cloudProviderServices.get(provider);
            if (service == null) {
                logger.error("Unsupported provider: {}. Available providers: {}", provider,
                        cloudProviderServices.keySet());
                throw new IllegalArgumentException("Unsupported provider: " + provider);
            }

            String name = params.get("name");
            String imageId = params.get("imageId");
            String size = params.get("size");
            String region = params.get("region");
            String sshKeyIdParam = params.get("sshKeyId");

            // Strip any tags from the imageId
            if (imageId != null && imageId.contains(":")) {
                imageId = imageId.split(":")[0];
            }

            logger.info("Instance details: name={}, imageId={}, size={}, region={}, sshKeyId={}", name, imageId, size,
                    region, sshKeyIdParam);

            // Added validation for AWS provider
            if ("AWS".equals(provider) && (imageId == null || imageId.isEmpty())) {
                throw new IllegalArgumentException(
                        "Image ID is required for AWS instances. Please select a valid image.");
            }

            if ("Local".equals(provider)) {
                if (imageId == null || imageId.isEmpty()) {
                    imageId = "ubuntu"; // Default image for local instances
                }
                if (size == null || size.isEmpty()) {
                    size = "default"; // Default size for local instances
                }
                if (region == null || region.isEmpty()) {
                    region = "local"; // Default region for local instances
                }
                logger.info("Using values for Local provider: imageId={}, size={}, region={}", imageId, size, region);
            }

            Long sshKeyId = null;
            if (sshKeyIdParam != null && !sshKeyIdParam.isEmpty()) {
                sshKeyId = Long.parseLong(sshKeyIdParam);
            }

            Instance instance = instanceService.createInstance(provider, name, imageId, size, region, sshKeyId);
            logger.info("Instance created successfully: {}", instance);

            if (instance.getPort() != null) {
                logger.info("Instance port: {}", instance.getPort());
                redirectAttributes.addFlashAttribute("instancePort", instance.getPort());
            }

            if (instance.getIp() != null) {
                logger.info("Instance IP: {}", instance.getIp().getHostAddress());
                redirectAttributes.addFlashAttribute("instanceIp", instance.getIp().getHostAddress());
            }

            if (sshKeyId != null) {
                SSHKey sshKey = sshKeyService.getSSHKeyById(sshKeyId);
                instance.setSshKey(sshKey);
            } else {
                logger.info("No SSH key found for instance: {}", instance.getId());
            }

            // Save the instance
            instanceService.addInstances(List.of(instance));

            redirectAttributes.addFlashAttribute("success", "Instance created successfully");
            return "redirect:/infrastructure";
        } catch (Exception e) {
            logger.error("Failed to create instance", e);
            redirectAttributes.addFlashAttribute("error", "Failed to create instance: " + e.getMessage());
            return "redirect:/instances/create";
        }
    }
}