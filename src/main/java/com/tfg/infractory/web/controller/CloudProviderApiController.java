package com.tfg.infractory.web.controller;

import java.util.List;
import java.util.Map;
import java.util.Collections;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.tfg.infractory.infrastructure.cloud.model.Size;
import com.tfg.infractory.infrastructure.cloud.service.CloudProviderService;
import com.tfg.infractory.infrastructure.cloud.service.AWSCloudProviderService;

/**
 * REST API controller for cloud provider operations
 */
@RestController
@RequestMapping("/api/cloud")
public class CloudProviderApiController {

    private static final Logger logger = LoggerFactory.getLogger(CloudProviderApiController.class);
    private final Map<String, CloudProviderService> cloudProviderServices;

    public CloudProviderApiController(List<CloudProviderService> cloudProviderServices) {
        this.cloudProviderServices = cloudProviderServices.stream()
                .collect(Collectors.toMap(
                        service -> {
                            String simpleName = service.getClass().getSimpleName();
                            return simpleName.equals("LocalProviderService") ? "Local"
                                    : simpleName.replace("CloudProviderService", "").replace("ProviderService", "");
                        },
                        Function.identity()));
        logger.info("Initialized cloud provider services for API: {}", this.cloudProviderServices.keySet());
    }

    /**
     * Get all available instance sizes for a specific provider
     * 
     * @param provider The provider name (AWS, DigitalOcean, etc.)
     * @return List of available sizes
     */
    @GetMapping("/{provider}/sizes")
    public List<Size> getAvailableSizes(@PathVariable String provider) {
        logger.info("Getting available sizes for provider: {}", provider);
        CloudProviderService service = cloudProviderServices.get(provider);
        if (service == null) {
            logger.warn("Provider not found: {}", provider);
            return Collections.emptyList();
        }
        return service.getAvailableSizes();
    }

    /**
     * Get compatible instance sizes for a specific image
     * 
     * @param provider The provider name (AWS, DigitalOcean, etc.)
     * @param imageId  The image ID to check compatibility for
     * @return List of compatible sizes
     */
    @GetMapping("/{provider}/compatible-sizes")
    public List<Size> getCompatibleSizes(
            @PathVariable String provider,
            @RequestParam String imageId,
            @RequestParam(required = false) String region) {
        logger.info("Getting compatible sizes for provider: {}, image: {}, region: {}", provider, imageId, region);

        CloudProviderService service = cloudProviderServices.get(provider);
        if (service == null) {
            logger.warn("Provider not found: {}", provider);
            return Collections.emptyList();
        }

        if (imageId == null || imageId.isEmpty()) {
            logger.warn("No image ID provided, returning all available sizes");
            return service.getAvailableSizes();
        }

        // For AWS, check region-specific compatibility if region is provided
        if ("AWS".equals(provider) && region != null && !region.isEmpty()
                && service instanceof AWSCloudProviderService) {
            AWSCloudProviderService awsService = (AWSCloudProviderService) service;
            return awsService.getRegionCompatibleSizesForImage(imageId, region);
        }

        return service.getCompatibleSizesForImage(imageId);
    }

    /**
     * Debugging endpoint to validate image IDs
     * 
     * @param provider The provider name (AWS, DigitalOcean, etc.)
     * @param imageId  The image ID to validate
     * @return Details about the image ID
     */
    @GetMapping("/{provider}/validate-image")
    public Map<String, Object> validateImageId(
            @PathVariable String provider,
            @RequestParam String imageId) {
        logger.info("Validating image ID for provider: {} and image: {}", provider, imageId);

        CloudProviderService service = cloudProviderServices.get(provider);
        if (service == null) {
            logger.warn("Provider not found: {}", provider);
            return Map.of(
                    "valid", false,
                    "error", "Provider not found: " + provider,
                    "providedImageId", imageId);
        }

        // Clean the image ID (for AWS)
        String cleanedImageId = imageId;
        if (imageId != null && (imageId.contains("[") || imageId.contains("]"))) {
            cleanedImageId = imageId.replace("[", "").replace("]", "");
        }

        // For AWS, check if it starts with ami-
        boolean validFormat = true;
        String formatError = null;

        if ("AWS".equals(provider) && (cleanedImageId == null || !cleanedImageId.startsWith("ami-"))) {
            validFormat = false;
            formatError = "AWS image IDs must start with 'ami-'";
        }

        return Map.of(
                "valid", validFormat && cleanedImageId != null && !cleanedImageId.isEmpty(),
                "originalImageId", imageId,
                "cleanedImageId", cleanedImageId,
                "error", formatError != null ? formatError : "None");
    }

    /**
     * Verify compatibility between region, image, and instance type
     * 
     * @param provider     The provider name (AWS)
     * @param imageId      The image ID
     * @param region       The region
     * @param instanceType The instance type
     * @return Compatibility verification result
     */
    @GetMapping("/{provider}/verify-compatibility")
    public Map<String, Object> verifyCompatibility(
            @PathVariable String provider,
            @RequestParam String imageId,
            @RequestParam String region,
            @RequestParam String instanceType) {
        logger.info("Verifying compatibility for provider: {}, image: {}, region: {}, instance type: {}",
                provider, imageId, region, instanceType);

        if (!"AWS".equals(provider)) {
            // For non-AWS providers, we currently don't do extensive compatibility checks
            return Map.of(
                    "compatible", true,
                    "message", "Compatibility check not implemented for this provider");
        }

        CloudProviderService service = cloudProviderServices.get(provider);
        if (service == null) {
            logger.warn("Provider not found: {}", provider);
            return Map.of(
                    "compatible", false,
                    "message", "Provider not found or not configured: " + provider);
        }

        if (!(service instanceof AWSCloudProviderService)) {
            return Map.of(
                    "compatible", true,
                    "message", "Not an AWS provider");
        }

        AWSCloudProviderService awsService = (AWSCloudProviderService) service;

        // Clean the image ID
        String cleanedImageId = imageId;
        if (imageId != null && (imageId.contains("[") || imageId.contains("]"))) {
            cleanedImageId = imageId.replace("[", "").replace("]", "");
        }

        // Step 1: Verify architecture compatibility
        boolean archCompatible = awsService.validateArchitectureCompatibility(cleanedImageId, instanceType);
        if (!archCompatible) {
            return Map.of(
                    "compatible", false,
                    "message", "Architecture mismatch between image and instance type. ARM-based instances require " +
                            "ARM-compatible images, and x86-based instances require x86-compatible images.");
        }

        // Step 2: Verify region compatibility
        boolean regionCompatible = awsService.validateRegionInstanceTypeCompatibility(region, instanceType);
        if (!regionCompatible) {
            return Map.of(
                    "compatible", false,
                    "message", "The selected instance type '" + instanceType + "' is not available in the region '" +
                            region + "'. Please select a different instance type or region.");
        }

        // All checks passed
        return Map.of(
                "compatible", true,
                "message", "Configuration is compatible");
    }
}