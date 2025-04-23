package com.tfg.infractory.infrastructure.cloud.service;

import java.util.*;
import org.slf4j.Logger;
import java.time.LocalDate;
import java.net.InetAddress;
import org.slf4j.LoggerFactory;
import java.util.stream.Collectors;
import java.net.UnknownHostException;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import com.tfg.infractory.domain.model.Instance;
import com.tfg.infractory.domain.model.Provider;
import com.tfg.infractory.infrastructure.cloud.model.Size;
import com.tfg.infractory.infrastructure.ssh.model.SSHKey;
import com.tfg.infractory.infrastructure.cloud.model.Image;
import com.tfg.infractory.infrastructure.cloud.model.Region;
import com.tfg.infractory.domain.repository.InstanceRepository;
import com.tfg.infractory.domain.repository.ProviderRepository;
import com.tfg.infractory.infrastructure.ssh.service.SSHKeyService;
import com.tfg.infractory.infrastructure.cloud.model.digitalocean.*;
import com.tfg.infractory.infrastructure.cloud.client.DigitalOceanClient;
import com.tfg.infractory.infrastructure.ssh.repository.SSHKeyRepository;
import com.tfg.infractory.infrastructure.ssh.service.RemoteCommandService;
import com.tfg.infractory.infrastructure.cloud.repository.DOSizeRepository;
import com.tfg.infractory.infrastructure.cloud.repository.DOImageRepository;
import com.tfg.infractory.infrastructure.cloud.repository.DORegionRepository;

@Service
public class DigitalOceanCloudProviderService implements CloudProviderService {
    private static final Logger logger = LoggerFactory.getLogger(DigitalOceanCloudProviderService.class);
    private static final int MAX_RETRIES = 10; // Increased retries
    private static final long RETRY_INTERVAL = 10000;

    private final DigitalOceanClient doClient;
    private final InstanceRepository instanceRepository;
    private final ProviderRepository providerRepository;
    private final DORegionRepository regionRepository;
    private final DOSizeRepository sizeRepository;
    private final DOImageRepository imageRepository;
    private final RemoteCommandService remoteCommandService;

    private LocalDate lastUpdateDate;

    @Autowired
    public DigitalOceanCloudProviderService(DigitalOceanClient doClient, InstanceRepository instanceRepository,
            ProviderRepository providerRepository, DORegionRepository regionRepository,
            DOSizeRepository sizeRepository, DOImageRepository imageRepository, SSHKeyRepository sshKeyRepository,
            SSHKeyService sshKeyService, RemoteCommandService remoteCommandService) {
        this.doClient = doClient;
        this.instanceRepository = instanceRepository;
        this.providerRepository = providerRepository;
        this.regionRepository = regionRepository;
        this.sizeRepository = sizeRepository;
        this.imageRepository = imageRepository;
        this.remoteCommandService = remoteCommandService;
    }

    @Override
    public Instance createInstance(String name, String imageId, String size, String region, SSHKey sshKey) {
        if (!doClient.isConfigured()) {
            logger.warn("DigitalOcean API token not configured. Cannot create instance.");
            return null;
        }
        logger.info("Creating DigitalOcean instance: name={}, imageId={}, size={}, region={}, sshKey={}", name, imageId,
                size, region, sshKey != null ? sshKey.getName() : "null");

        try {
            validateInstanceParameters(size, region);
            Droplet droplet = createDropletRequest(name, imageId, size, region, sshKey);
            Droplet createdDroplet = doClient.createDroplet(droplet);

            if (createdDroplet == null || createdDroplet.getId() == null) {
                throw new RuntimeException("Failed to create droplet");
            }

            logger.info("Droplet created successfully: id={}", createdDroplet.getId());

            Droplet completeDroplet = waitForDropletIp(createdDroplet.getId());
            logDropletDetails(completeDroplet);

            // After instance creation, install Docker with enhanced retry logic
            if (sshKey != null && sshKey.getPrivateKeySecretName() != null
                    && !sshKey.getPrivateKeySecretName().isEmpty()) {
                String privateKeySecretName = sshKey.getPrivateKeySecretName();

                // Modified command to handle apt lock
                String command = "until sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do " +
                        "echo 'Waiting for apt lock...'; sleep 5; done; " +
                        "curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh";

                int maxRetryAttempts = MAX_RETRIES;
                int retryCount = 0;
                boolean installationSuccess = false;

                while (retryCount < maxRetryAttempts && !installationSuccess) {
                    try {
                        remoteCommandService.executeCommand(
                                completeDroplet.getPublicIpv4Address().orElse(null),
                                "root",
                                privateKeySecretName,
                                command,
                                300);
                        logger.info("Docker installation command executed successfully on instance: {}",
                                createdDroplet.getId());
                        installationSuccess = true;
                    } catch (Exception e) {
                        if (e.getMessage() != null &&
                                (e.getMessage().contains("E: Could not get lock /var/lib/apt/lists/lock") ||
                                        e.getMessage().contains("E: Could not get lock /var/lib/dpkg/lock-frontend"))) {
                            retryCount++;
                            logger.warn(
                                    "Apt lock detected while installing Docker. Retrying installation... Attempt {}/{}",
                                    retryCount, maxRetryAttempts);
                            if (retryCount >= maxRetryAttempts) {
                                throw new RuntimeException("Failed to install Docker after " + maxRetryAttempts
                                        + " attempts due to apt lock.", e);
                            }
                            // Wait before retrying
                            Thread.sleep(10000); // 10 seconds
                        } else {
                            throw e; // Re-throw if it's a different exception
                        }
                    }
                }
            } else {
                logger.warn("SSH key or private key secret name is missing. Skipping Docker installation.");
            }

            return saveInstance(name, imageId, size, region, sshKey, createdDroplet);
        } catch (Exception e) {
            logger.error("Error creating DigitalOcean instance", e);
            throw new RuntimeException("Failed to create instance: " + e.getMessage(), e);
        }
    }

    private Droplet waitForDropletIp(Long dropletId) throws InterruptedException {
        Droplet droplet;
        int retries = 0;
        while (retries < MAX_RETRIES) {
            droplet = doClient.getDroplet(dropletId);
            if (droplet != null && droplet.getPublicIpv4Address().isPresent()) {
                return droplet;
            }
            Thread.sleep(RETRY_INTERVAL);
            retries++;
        }
        throw new RuntimeException("Failed to get IP address for droplet: " + dropletId);
    }

    private void validateInstanceParameters(String size, String region) {
        if (doClient.getSize(size) == null) {
            throw new IllegalArgumentException("Invalid size: " + size);
        }
        if (doClient.getRegion(region) == null) {
            throw new IllegalArgumentException("Invalid region: " + region);
        }
    }

    private Droplet createDropletRequest(String name, String imageId, String size, String region, SSHKey sshKey) {
        Droplet droplet = new Droplet();
        droplet.setName(name);
        droplet.setImage(imageId);
        droplet.setSize(size);
        droplet.setRegion(region);

        if (sshKey != null) {
            String doKeyId = uploadSshKeyIfNeeded(sshKey);
            if (doKeyId != null) {
                droplet.setSshKeys(Collections.singletonList(doKeyId));
                logger.info("Setting SSH key for droplet creation: {}", doKeyId);
            } else {
                logger.warn("Failed to upload or verify SSH key. Instance will be created without SSH key.");
            }
        } else {
            logger.warn("No SSH key provided. Instance will be created without SSH key.");
        }

        return droplet;
    }

    private void logDropletDetails(Droplet completeDroplet) {
        if (completeDroplet == null) {
            logger.warn("Unable to fetch complete droplet details");
        } else {
            logger.info("Retrieved complete Droplet details: {}", completeDroplet);
            if (completeDroplet.getSshKeys() != null && !completeDroplet.getSshKeys().isEmpty()) {
                // logger.info("SSH keys associated with the Droplet: {}",
                // completeDroplet.getSshKeys());
            } else {
                // logger.warn("No SSH keys found associated with the Droplet");
            }
        }
    }

    private Instance saveInstance(String name, String imageId, String size, String region, SSHKey sshKey,
            Droplet createdDroplet) {
        Provider provider = providerRepository.findById("DigitalOcean")
                .orElseGet(() -> providerRepository.save(new Provider("DigitalOcean")));

        InetAddress ipAddress = null;
        try {
            if (createdDroplet.getPublicIpv4Address().isPresent()) {
                ipAddress = InetAddress.getByName(createdDroplet.getPublicIpv4Address().get());
            }
        } catch (UnknownHostException e) {
            logger.error("Failed to parse IP address for droplet: {}", createdDroplet.getId(), e);
        }

        Instance instance = new Instance(provider, region, ipAddress);
        instance.setName(name);
        instance.setImageId(imageId);
        instance.setSize(size);
        instance.setStatus(Instance.InstanceStatus.CREATING);
        instance.setSshKey(sshKey);
        instance.setProviderId(String.valueOf(createdDroplet.getId()));

        Instance savedInstance = instanceRepository.save(instance);
        logger.info("Instance saved to database: id={}, ip={}", savedInstance.getId(), ipAddress);

        return savedInstance;
    }

    public InetAddress getInstanceIp(String instanceId) {
        if (!doClient.isConfigured()) {
            logger.warn("DigitalOcean API token not configured. Cannot get instance IP.");
            return null;
        }
        if (instanceId == null || instanceId.isEmpty()) {
            throw new IllegalArgumentException("Instance ID cannot be null or empty");
        }

        try {
            Long id = Long.parseLong(instanceId);
            Droplet droplet = doClient.getDroplet(id);
            if (droplet == null || droplet.getNetworks() == null) {
                throw new RuntimeException("Unable to retrieve network information for instance " + instanceId);
            }

            return InetAddress.getByName(droplet.getPublicIpv4Address()
                    .orElseThrow(() -> new RuntimeException("No public IP address found for instance " + instanceId)));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid instance ID format: " + instanceId, e);
        } catch (UnknownHostException e) {
            throw new RuntimeException("Unable to resolve host for instance " + instanceId, e);
        }
    }

    @Override
    public void deleteInstance(String instanceId) {
        if (!doClient.isConfigured()) {
            logger.warn("DigitalOcean API token not configured. Cannot delete instance.");
            return;
        }
        doClient.deleteDroplet(Long.parseLong(instanceId));
    }

    public List<Region> getAvailableRegions() {
        if (!doClient.isConfigured()) {
            logger.warn("DigitalOcean API token not configured. Returning empty region list.");
            return new ArrayList<>();
        }
        return regionRepository.findAll().stream()
                .map(this::convertToRegion)
                .sorted((r1, r2) -> Boolean.compare(r2.isAvailable(), r1.isAvailable()))
                .collect(Collectors.toList());
    }

    @Override
    public List<Size> getAvailableSizes() {
        if (!doClient.isConfigured()) {
            logger.warn("DigitalOcean API token not configured. Returning empty size list.");
            return new ArrayList<>();
        }
        List<DOSize> sizes = sizeRepository.findAll().stream()
                .map(this::convertToSize)
                .sorted(Comparator.comparing(DOSize::getPriceHourly))
                .collect(Collectors.toList());
        logger.info("Retrieved {} sizes from the database", sizes.size());
        return new ArrayList<>(sizes);
    }

    @PostConstruct
    public void init() {
        try {
            updateDataIfNeeded();
        } catch (Exception e) {
            logger.error("Error initializing DigitalOceanClient", e);
        }
    }

    private boolean shouldUpdate() {
        LocalDate today = LocalDate.now();
        if (lastUpdateDate == null || lastUpdateDate.isBefore(today)) {
            lastUpdateDate = today;
            return true;
        }
        return false;
    }

    private void updateDataIfNeeded() {
        if (shouldUpdate()) {
            fetchAndStoreSizes();
            fetchAndStoreRegions();
            fetchAndStoreImages();
        }
    }

    private void fetchAndStoreRegions() {
        List<DORegion> fetchedRegions = doClient.getAllRegions();
        List<DORegionEntity> regionEntities = fetchedRegions.stream()
                .map(this::convertToRegionEntity)
                .collect(Collectors.toList());

        regionRepository.saveAll(regionEntities);
    }

    private void fetchAndStoreSizes() {
        List<DOSize> fetchedSizes = doClient.getAllSizes();
        if (fetchedSizes == null || fetchedSizes.isEmpty()) {
            logger.warn("No sizes fetched from the API");
            return;
        }
        List<DOSizeEntity> sizeEntities = fetchedSizes.stream()
                .map(this::convertToSizeEntity)
                .collect(Collectors.toList());
        sizeRepository.saveAll(sizeEntities);
    }

    private void logImages(List<Image> images) {
        logger.info("Fetched {} images from DigitalOcean", images.size());
        for (Image image : images) {
            logger.debug("Image: {}", image);
        }
    }

    private void fetchAndStoreImages() {
        List<Image> fetchedImages = doClient.getAllImages();
        if (fetchedImages == null || fetchedImages.isEmpty()) {
            logger.warn("No images fetched from the API");
            return;
        }
        List<DOImageEntity> imageEntities = fetchedImages.stream()
                .map(this::convertToImageEntity)
                .collect(Collectors.toList());
        imageRepository.saveAll(imageEntities);
    }

    private DORegionEntity convertToRegionEntity(DORegion region) {
        DORegionEntity entity = new DORegionEntity();
        entity.setSlug(region.getSlug());
        entity.setName(region.getName());
        entity.setAvailable(region.isAvailable());
        return entity;
    }

    private DOSizeEntity convertToSizeEntity(DOSize size) {
        DOSizeEntity entity = new DOSizeEntity();
        entity.setSlug(size.getSlug());
        entity.setName(size.getDescription());
        entity.setMemory(size.getMemory());
        entity.setVcpus(size.getVcpus());
        entity.setDisk(size.getDisk());
        entity.setPriceMonthly(size.getPriceMonthly());
        entity.setPriceHourly(size.getPriceHourly());
        return entity;
    }

    private DOImageEntity convertToImageEntity(Image image) {
        DOImageEntity entity = new DOImageEntity();

        // Handle the ID conversion - Object to Long
        Object imageId = image.getId();
        if (imageId != null) {
            if (imageId instanceof Long) {
                entity.setId((Long) imageId);
            } else if (imageId instanceof Number) {
                entity.setId(((Number) imageId).longValue());
            } else {
                try {
                    // Try to parse the ID as a Long if it's a String
                    entity.setId(Long.parseLong(imageId.toString()));
                } catch (NumberFormatException e) {
                    logger.warn("Could not convert image ID {} to Long. Using null instead.", imageId);
                    entity.setId(null);
                }
            }
        } else {
            entity.setId(null);
        }

        entity.setName(image.getName());
        entity.setDistribution(image.getDistribution());
        entity.setSlug(image.getSlug());
        entity.setPublic(image.isPublic());
        entity.setRegions(image.getRegions());
        entity.setCreatedAt(image.getCreatedAt());
        entity.setType(image.getType());
        entity.setMinDiskSize(image.getMinDiskSize());
        entity.setSizeGigabytes(image.getSizeGigabytes());
        entity.setDescription(image.getDescription());
        entity.setTags(image.getTags());
        entity.setStatus(image.getStatus());
        entity.setErrorMessage(image.getErrorMessage());
        return entity;
    }

    private DORegion convertToRegion(DORegionEntity entity) {
        DORegion region = new DORegion();
        region.setSlug(entity.getSlug());
        region.setName(entity.getName());
        region.setAvailable(entity.isAvailable());
        return region;
    }

    private DOSize convertToSize(DOSizeEntity entity) {
        DOSize size = new DOSize();
        size.setSlug(entity.getSlug());
        size.setDescription(entity.getName());
        size.setMemory(entity.getMemory());
        size.setVcpus(entity.getVcpus());
        size.setDisk(entity.getDisk());
        size.setPriceMonthly(entity.getPriceMonthly());
        size.setPriceHourly(entity.getPriceHourly());
        return size;
    }

    private Image convertToImage(DOImageEntity entity) {
        return new Image(
                entity.getId(),
                entity.getName(),
                entity.getDistribution(),
                entity.getSlug(),
                entity.isPublic(),
                entity.getRegions(),
                entity.getCreatedAt(),
                entity.getType(),
                entity.getMinDiskSize(),
                entity.getSizeGigabytes(),
                entity.getDescription(),
                entity.getTags(),
                entity.getStatus(),
                entity.getErrorMessage());
    }

    public DORegion getRegion(String slug) {
        return regionRepository.findById(slug)
                .map(this::convertToRegion)
                .orElse(null);
    }

    public DOSize getSize(String slug) {
        return sizeRepository.findById(slug)
                .map(this::convertToSize)
                .orElse(null);
    }

    public List<DOSize> getAllSizes() {
        return sizeRepository.findAll().stream()
                .map(this::convertToSize)
                .collect(Collectors.toList());
    }

    @Override
    public List<Image> getAllImages() {
        if (!doClient.isConfigured()) {
            logger.warn("DigitalOcean API token not configured. Returning empty image list.");
            return new ArrayList<>();
        }
        List<Image> images = imageRepository.findAll().stream()
                .map(this::convertToImage)
                .collect(Collectors.toList());
        logger.info("Retrieved {} images from the database", images.size());
        if (images.isEmpty()) {
            logger.info("No images found in the database. Fetching from DigitalOcean API.");
            images = doClient.getAllImages();
            logImages(images);
            List<DOImageEntity> imageEntities = images.stream()
                    .map(this::convertToImageEntity)
                    .collect(Collectors.toList());
            imageRepository.saveAll(imageEntities);
            logger.info("Saved {} images to the database", imageEntities.size());
        }
        return images;
    }

    public List<Image> getImagesForRegion(String regionSlug) {
        return getAllImages().stream()
                .filter(image -> image.getRegions().contains(regionSlug))
                .collect(Collectors.toList());
    }

    @Override
    public boolean isConfigured() {
        return doClient.isConfigured();
    }

    @Override
    public Instance.InstanceStatus getInstanceStatus(String instanceId) {
        if (!doClient.isConfigured()) {
            logger.warn("DigitalOcean API token not configured. Cannot get instance status.");
            return Instance.InstanceStatus.ERROR;
        }

        try {
            Long id = Long.parseLong(instanceId);
            Droplet droplet = doClient.getDroplet(id);

            if (droplet == null) {
                logger.warn("No droplet found for instance ID: {}", instanceId);
                return Instance.InstanceStatus.ERROR;
            }

            String status = droplet.getStatus();
            if (status == null) {
                logger.warn("Null status received for instance ID: {}", instanceId);
                return Instance.InstanceStatus.ERROR;
            }

            switch (status.toLowerCase()) {
                case "new":
                    return Instance.InstanceStatus.CREATING;
                case "active":
                    return Instance.InstanceStatus.RUNNING;
                case "off":
                    return Instance.InstanceStatus.STOPPED;
                case "archive":
                    return Instance.InstanceStatus.DELETED;
                default:
                    logger.warn("Unknown status '{}' for instance ID: {}", status, instanceId);
                    return Instance.InstanceStatus.ERROR;
            }
        } catch (NumberFormatException e) {
            logger.error("Invalid instance ID format: {}", instanceId, e);
            return Instance.InstanceStatus.ERROR;
        } catch (Exception e) {
            logger.error("Error getting instance status for ID: {}", instanceId, e);
            return Instance.InstanceStatus.ERROR;
        }
    }

    public String uploadSshKeyIfNeeded(SSHKey sshKey) {
        try {
            List<DOSSHKey> existingKeys = doClient.getAllSshKeys();
            Optional<DOSSHKey> matchingKey = existingKeys.stream()
                    .filter(key -> key.getFingerprint().equals(sshKey.getFingerprint()))
                    .findFirst();

            if (matchingKey.isPresent()) {
                logger.info("SSH key already exists on DigitalOcean: {}", matchingKey.get().getId());
                return String.valueOf(matchingKey.get().getId());
            } else {
                logger.info("SSH key not found on DigitalOcean. Uploading key: {}", sshKey.getName());
                DOSSHKey createdKey = doClient.createSshKey(sshKey.getName(), sshKey.getPublicKey());
                if (createdKey == null) {
                    logger.error("Failed to create SSH key on DigitalOcean");
                    return null;
                }
                logger.info("SSH key uploaded successfully: {}", createdKey.getId());

                int maxRetries = 10;
                int retryDelay = 2000;
                for (int i = 0; i < maxRetries; i++) {
                    if (doClient.sshKeyExists(createdKey.getFingerprint())) {
                        logger.info("SSH key is now available on DigitalOcean");
                        return String.valueOf(createdKey.getId());
                    }
                    logger.info("Waiting for SSH key to be available... Attempt {}/{}", i + 1, maxRetries);
                    Thread.sleep(retryDelay);
                }
                logger.warn("SSH key not available after {} attempts", maxRetries);
                return null;
            }
        } catch (Exception e) {
            logger.error("Failed to upload SSH key to DigitalOcean", e);
            return null;
        }
    }

    public void deleteSshKeyFromProvider(SSHKey sshKey) {
        try {
            doClient.deleteSshKey(sshKey.getFingerprint());
            logger.info("SSH key deleted from DigitalOcean using fingerprint: {}", sshKey.getFingerprint());
        } catch (Exception e) {
            logger.warn("Failed to delete SSH key from DigitalOcean using fingerprint. Attempting to delete by ID.", e);
            try {
                DOSSHKey doSshKey = doClient.getSshKeyByFingerprint(sshKey.getFingerprint());
                if (doSshKey != null) {
                    doClient.deleteSshKey(doSshKey.getId().toString());
                    logger.info("SSH key deleted from DigitalOcean using ID: {}", doSshKey.getId());
                } else {
                    logger.warn("SSH key not found on DigitalOcean: {}", sshKey.getFingerprint());
                }
            } catch (Exception ex) {
                logger.error("Failed to delete SSH key from DigitalOcean", ex);
            }
        }
    }
}