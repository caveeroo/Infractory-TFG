package com.tfg.infractory.infrastructure.cloud.service;

import java.util.List;
import org.slf4j.Logger;
import java.util.ArrayList;
import java.net.InetAddress;
import java.time.LocalDate;
import java.util.Collections;
import org.slf4j.LoggerFactory;
import java.util.stream.Collectors;
import java.net.UnknownHostException;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.retry.RetryPolicy;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.*;

import com.tfg.infractory.domain.model.Instance;
import com.tfg.infractory.domain.model.Provider;
import com.tfg.infractory.infrastructure.cloud.model.Size;
import com.tfg.infractory.infrastructure.ssh.model.SSHKey;
import com.tfg.infractory.infrastructure.ssh.service.RemoteCommandService;
import com.tfg.infractory.infrastructure.cloud.model.aws.AWSSize;
import com.tfg.infractory.infrastructure.cloud.model.aws.AWSRegion;
import com.tfg.infractory.domain.exception.InstanceNotFoundException;
import com.tfg.infractory.domain.repository.ProviderRepository;
import com.tfg.infractory.domain.repository.InstanceRepository;

import java.util.Date;
import java.time.Instant;
import java.util.Base64;
import java.util.Comparator;
import java.util.Set;

@Service
public class AWSCloudProviderService implements CloudProviderService {

    private static final Logger logger = LoggerFactory.getLogger(AWSCloudProviderService.class);
    private static final int MAX_RETRIES = 10;
    // private static final long RETRY_INTERVAL = 3000;

    @Value("${aws.accessKey:#{null}}")
    private String awsAccessKey;

    @Value("${aws.secretKey:#{null}}")
    private String awsSecretKey;

    @Value("${aws.region:#{null}}")
    private String awsRegion;

    private final ProviderRepository providerRepository;
    private final InstanceRepository instanceRepository;

    private final RemoteCommandService remoteCommandService;

    private List<com.tfg.infractory.infrastructure.cloud.model.Image> cachedImages;
    private List<AWSSize> cachedSizes;
    private List<AWSRegion> cachedRegions;
    private LocalDate lastUpdateDate;

    public AWSCloudProviderService(ProviderRepository providerRepository, InstanceRepository instanceRepository,
            RemoteCommandService remoteCommandService) {
        this.providerRepository = providerRepository;
        this.instanceRepository = instanceRepository;
        this.remoteCommandService = remoteCommandService;
        this.cachedImages = new ArrayList<>();
        this.cachedSizes = new ArrayList<>();
        this.cachedRegions = new ArrayList<>();
    }

    @PostConstruct
    public void init() {
        try {
            updateDataIfNeeded();
        } catch (Exception e) {
            logger.error("Failed to initialize AWS client", e);
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
            logger.info("Updating cached AWS data");
            cachedRegions = fetchRegions();
            cachedSizes = fetchSizes();

            // Default to eu-north-1 for initial image cache
            cachedImages = fetchImages("eu-north-1");

            lastUpdateDate = LocalDate.now();
        }
    }

    /**
     * Gets an EC2 client for a specific region.
     * 
     * @param regionName The AWS region to use, or null to use the default
     *                   configured region
     * @return The EC2 client, or null if credentials are not configured
     */
    private Ec2Client getEc2Client(String regionName) {
        if (!isConfigured()) {
            logger.warn("AWS credentials are not configured");
            return null;
        }

        try {
            AwsBasicCredentials awsCreds = AwsBasicCredentials.create(awsAccessKey, awsSecretKey);

            // Use the provided region if specified, otherwise fall back to the configured
            // default
            String regionToUse = (regionName != null && !regionName.isEmpty()) ? regionName : awsRegion;

            return Ec2Client.builder()
                    .credentialsProvider(StaticCredentialsProvider.create(awsCreds))
                    .region(Region.of(regionToUse))
                    .overrideConfiguration(c -> c.retryPolicy(RetryPolicy.builder().numRetries(MAX_RETRIES).build()))
                    .build();
        } catch (Exception e) {
            logger.error("Failed to create EC2 client for region {}: {}", regionName, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Gets an EC2 client using the default configured region.
     * 
     * @return The EC2 client, or null if credentials are not configured
     */
    private Ec2Client getEc2Client() {
        return getEc2Client(null);
    }

    @Override
    public Instance createInstance(String name, String imageId, String size, String region, SSHKey sshKey) {
        if (!isConfigured()) {
            throw new IllegalStateException("AWS credentials are not configured");
        }

        if (imageId == null || imageId.isEmpty()) {
            throw new IllegalArgumentException("Image ID is required for AWS instances. Expected format: ami-xxxxxxxx");
        }

        if (size == null || region == null) {
            throw new IllegalArgumentException("Size and region are required");
        }

        // Clean the image ID to handle formatting issues
        String cleanedImageId = imageId;
        if (cleanedImageId.contains("[") || cleanedImageId.contains("]")) {
            cleanedImageId = cleanedImageId.replace("[", "").replace("]", "");
            logger.info("Cleaned image ID from {} to {}", imageId, cleanedImageId);
        }

        // Ensure ami- prefix
        if (!cleanedImageId.startsWith("ami-")) {
            logger.warn("Image ID does not have expected 'ami-' prefix: {}", cleanedImageId);
        }

        // Validate architecture compatibility
        if (!validateArchitectureCompatibility(cleanedImageId, size)) {
            throw new IllegalArgumentException(
                    "Architecture mismatch between image and instance type. " +
                            "ARM-based instances require ARM-compatible images, and " +
                            "x86-based instances require x86-compatible images.");
        }

        // Validate region compatibility with instance type
        if (!validateRegionInstanceTypeCompatibility(region, size)) {
            throw new IllegalArgumentException(
                    "The selected instance type '" + size + "' is not available in the region '" + region + "'. " +
                            "Please select a different instance type or region.");
        }

        logger.info("Creating AWS instance with name={}, imageId={}, size={}, region={}",
                name, imageId, size, region);

        String regionToUse = (region != null && !region.isEmpty()) ? region : "eu-north-1";
        logger.info("Using region: {}", regionToUse);

        // Get EC2 client for the specific region
        Ec2Client ec2 = getEc2Client(regionToUse);

        try {
            // Get or create security group
            String securityGroupId = createOrGetSecurityGroup(ec2, "infractory-security-group");

            // Find available subnet in the default VPC
            String subnetId = getDefaultSubnet(ec2);
            if (subnetId == null) {
                throw new RuntimeException("No default subnet found in the specified region: " + regionToUse);
            }

            // Log the default username for SSH access based on the image
            String defaultUser = getDefaultUserForImage(cleanedImageId);
            logger.info(
                    "Instance will be created with default user '{}'. Use this username instead of 'root' for SSH access.",
                    defaultUser);

            // Upload SSH key if provided and not already in AWS
            String keyName = null;
            if (sshKey != null && sshKey.getPublicKey() != null) {
                keyName = uploadSshKeyIfNeeded(ec2, sshKey);
            }

            // Prepare user data script for initial setup
            String userData = "#!/bin/bash\n" +
                    "exec > >(tee /var/log/user-data.log) 2>&1\n" +
                    "echo 'Starting instance initialization...'\n" +
                    "# Helper function for logging\n" +
                    "log_cmd() {\n" +
                    "  echo \"Running: $1\"\n" +
                    "  eval \"$1\"\n" +
                    "  local status=$?\n" +
                    "  if [ $status -eq 0 ]; then\n" +
                    "    echo \"Command succeeded: $1\"\n" +
                    "  else\n" +
                    "    echo \"Command failed with status $status: $1\"\n" +
                    "  fi\n" +
                    "  return $status\n" +
                    "}\n" +
                    "# Configure SSH access to allow root login\n" +
                    "log_cmd \"grep '^PermitRootLogin' /etc/ssh/sshd_config || echo 'No PermitRootLogin setting found'\"\n"
                    +
                    "log_cmd \"sed -i 's/^#\\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config\"\n"
                    +
                    "log_cmd \"sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config\"\n"
                    +
                    "log_cmd \"sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config\"\n" +
                    "# Add PermitRootLogin yes if not present\n" +
                    "if ! grep -q \"^PermitRootLogin\" /etc/ssh/sshd_config; then\n" +
                    "  log_cmd \"echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config\"\n" +
                    "fi\n" +
                    "log_cmd \"grep '^PermitRootLogin' /etc/ssh/sshd_config\"\n" +
                    "# Create root .ssh directory if it doesn't exist\n" +
                    "log_cmd \"mkdir -p /root/.ssh\"\n" +
                    "log_cmd \"chmod 700 /root/.ssh\"\n" +
                    "# Get default user's SSH key\n" +
                    "DEFAULT_USER_KEY=\"\"\n" +
                    "if [ -f \"/home/" + defaultUser + "/.ssh/authorized_keys\" ]; then\n" +
                    "  DEFAULT_USER_KEY=$(cat /home/" + defaultUser + "/.ssh/authorized_keys)\n" +
                    "  echo \"Found default user's SSH key\"\n" +
                    "else\n" +
                    "  echo \"Default user authorized_keys not found at /home/" + defaultUser
                    + "/.ssh/authorized_keys\"\n" +
                    "fi\n" +
                    "# Clean up any restrictions in root's authorized_keys if it exists\n" +
                    "if [ -f /root/.ssh/authorized_keys ]; then\n" +
                    "  echo \"Root's authorized_keys exists, cleaning it up\"\n" +
                    "  # Replace command restriction with empty string\n" +
                    "  log_cmd \"sed -i 's/^no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command=.*ssh-/ssh-/' /root/.ssh/authorized_keys\"\n"
                    +
                    "  # Also try another pattern that might be used\n" +
                    "  log_cmd \"sed -i 's/^.*command=\\\"echo.*Please login as the user.*\\\".*//' /root/.ssh/authorized_keys\"\n"
                    +
                    "  # Remove empty lines\n" +
                    "  log_cmd \"sed -i '/^$/d' /root/.ssh/authorized_keys\"\n" +
                    "else\n" +
                    "  echo \"Creating new authorized_keys for root\"\n" +
                    "fi\n" +
                    "# Write the default user's key to root's authorized_keys if available\n" +
                    "if [ ! -z \"$DEFAULT_USER_KEY\" ]; then\n" +
                    "  echo \"Adding default user's key to root's authorized_keys\"\n" +
                    "  echo \"$DEFAULT_USER_KEY\" > /root/.ssh/authorized_keys\n" +
                    "  log_cmd \"chmod 600 /root/.ssh/authorized_keys\"\n" +
                    "  log_cmd \"chown root:root /root/.ssh/authorized_keys\"\n" +
                    "  echo \"Final root's authorized_keys content:\"\n" +
                    "  log_cmd \"cat /root/.ssh/authorized_keys\"\n" +
                    "fi\n" +
                    "# Fix any permission issues\n" +
                    "log_cmd \"chown -R root:root /root/.ssh\"\n" +
                    "log_cmd \"systemctl restart sshd\"\n" +
                    "# Create a sudo rule for the default user to avoid password prompts\n" +
                    "echo \"" + defaultUser + " ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/" + defaultUser + "\n" +
                    "chmod 440 /etc/sudoers.d/" + defaultUser + "\n" +
                    "echo 'SSH configured for root access'\n" +
                    "echo 'Instance setup complete'\n";

            // Convert user data to Base64 encoding as required by AWS
            String base64UserData = Base64.getEncoder().encodeToString(userData.getBytes());

            // Build the RunInstancesRequest
            Tag nameTag = Tag.builder()
                    .key("Name")
                    .value(name)
                    .build();

            RunInstancesRequest runRequest = RunInstancesRequest.builder()
                    .imageId(cleanedImageId)
                    .instanceType(size)
                    .maxCount(1)
                    .minCount(1)
                    .keyName(keyName)
                    .securityGroupIds(securityGroupId)
                    .subnetId(subnetId)
                    .userData(base64UserData)
                    .metadataOptions(InstanceMetadataOptionsRequest.builder()
                            .httpTokens("optional")
                            .httpPutResponseHopLimit(2)
                            .httpEndpoint("enabled")
                            .build())
                    .tagSpecifications(TagSpecification.builder()
                            .resourceType(ResourceType.INSTANCE)
                            .tags(nameTag)
                            .build())
                    .build();

            RunInstancesResponse response = ec2.runInstances(runRequest);
            if (response.instances().isEmpty()) {
                throw new RuntimeException("Failed to create AWS instance. No instance data returned.");
            }

            // Extract the instance ID
            String instanceId = response.instances().get(0).instanceId();
            logger.info("AWS instance created with ID: {}", instanceId);

            // Wait for the instance to be running and get its public IP
            InetAddress ipAddress = waitForRunningInstanceWithExponentialBackoff(ec2, instanceId);

            if (ipAddress == null) {
                throw new RuntimeException("Failed to get IP address for instance: " + instanceId);
            }

            logger.info("AWS instance {} is running with IP: {}", instanceId, ipAddress.getHostAddress());

            // The instance might need additional time to initialize SSH and other services
            allowInstanceInitialization(ipAddress, 45);

            // After instance creation, install Docker with retry logic
            if (sshKey != null && sshKey.getPrivateKeySecretName() != null
                    && !sshKey.getPrivateKeySecretName().isEmpty()) {
                // Get the appropriate user for the specific image
                String user = getDefaultUserForImage(cleanedImageId);
                String privateKeySecretName = sshKey.getPrivateKeySecretName();

                // Simplified Docker installation command without complex apt lock checking
                String command = "curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh";

                int maxRetryAttempts = MAX_RETRIES;
                int retryCount = 0;
                boolean installationSuccess = false;

                logger.info("Attempting to install Docker on AWS instance: {}", instanceId);

                while (retryCount < maxRetryAttempts && !installationSuccess) {
                    try {
                        remoteCommandService.executeCommand(
                                ipAddress.getHostAddress(),
                                user,
                                privateKeySecretName,
                                command,
                                300);
                        logger.info("Docker installation command executed successfully on AWS instance: {}",
                                instanceId);
                        installationSuccess = true;

                        // Add current user to docker group to avoid needing sudo for docker commands
                        try {
                            remoteCommandService.executeCommand(
                                    ipAddress.getHostAddress(),
                                    user,
                                    privateKeySecretName,
                                    "sudo usermod -aG docker $USER && sudo systemctl enable docker",
                                    60);
                            logger.info("Added user to docker group and enabled docker service on instance: {}",
                                    instanceId);
                        } catch (Exception e) {
                            logger.warn(
                                    "Could not add user to docker group, but Docker installation was successful: {}",
                                    e.getMessage());
                        }
                    } catch (Exception e) {
                        retryCount++;
                        logger.warn("Docker installation failed. Retrying ({}/{}): {}", retryCount, maxRetryAttempts,
                                e.getMessage());
                        if (retryCount >= maxRetryAttempts) {
                            logger.error("Failed to install Docker after {} attempts", maxRetryAttempts);
                        } else {
                            Thread.sleep(15000);
                        }
                    }
                }
            } else {
                logger.warn("SSH key or private key secret name is missing. Skipping Docker installation.");
            }

            // Create and save the instance using the original imageId for reference
            return saveInstance(name, imageId, size, regionToUse, sshKey, instanceId, ipAddress);

        } catch (Exception e) {
            logger.error("Failed to create AWS instance: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create instance with provider: AWS", e);
        }
    }

    /**
     * Allows time for the instance to fully initialize its services.
     * Attempts to verify reachability but continues even if verification fails.
     * 
     * @param ipAddress      The IP address to check
     * @param maxWaitSeconds Maximum seconds to wait
     */
    private void allowInstanceInitialization(InetAddress ipAddress, int maxWaitSeconds) {
        logger.info("Allowing instance initialization time (up to {} seconds)...", maxWaitSeconds);

        boolean reachable = false;
        for (int i = 0; i < 3; i++) {
            try {
                logger.info("Attempting to verify reachability of instance at {} (attempt {}/3)",
                        ipAddress.getHostAddress(), i + 1);
                reachable = ipAddress.isReachable(10000);
                if (reachable) {
                    logger.info("Instance at {} is responding to ping", ipAddress.getHostAddress());
                    break;
                }
                logger.info("Instance at {} not yet responding to ping", ipAddress.getHostAddress());
                Thread.sleep(5000);
            } catch (Exception e) {
                logger.warn("Failed to check reachability of instance at {}: {}",
                        ipAddress.getHostAddress(), e.getMessage());
            }
        }

        if (!reachable) {
            logger.warn("Instance at {} is not responding to ping. This is often normal with AWS instances " +
                    "due to security or firewall settings. SSH access may still work.", ipAddress.getHostAddress());
        }

        try {
            int waitTime = reachable ? 5 : 20; // Wait longer if ping failed
            logger.info("Waiting {} more seconds for instance services to initialize...", waitTime);
            Thread.sleep(waitTime * 1000);
            logger.info("Instance initialization time complete");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Gets a default subnet from the default VPC.
     * 
     * @param ec2 The EC2 client
     * @return A subnet ID or null if none found
     */
    private String getDefaultSubnet(Ec2Client ec2) {
        try {
            // First find the default VPC
            DescribeVpcsRequest vpcRequest = DescribeVpcsRequest.builder()
                    .filters(
                            Filter.builder().name("isDefault").values("true").build())
                    .build();

            DescribeVpcsResponse vpcResponse = ec2.describeVpcs(vpcRequest);
            if (vpcResponse.vpcs().isEmpty()) {
                logger.warn("No default VPC found. This may cause instance creation to fail.");
                return null;
            }

            String vpcId = vpcResponse.vpcs().get(0).vpcId();
            logger.info("Using default VPC: {}", vpcId);

            // Find a subnet in the default VPC
            DescribeSubnetsRequest subnetRequest = DescribeSubnetsRequest.builder()
                    .filters(
                            Filter.builder().name("vpc-id").values(vpcId).build(),
                            Filter.builder().name("state").values("available").build())
                    .build();

            DescribeSubnetsResponse subnetResponse = ec2.describeSubnets(subnetRequest);
            if (subnetResponse.subnets().isEmpty()) {
                logger.warn("No subnets found in default VPC {}. This may cause instance creation to fail.", vpcId);
                return null;
            }

            // Prefer a subnet with public IPs enabled
            return subnetResponse.subnets().stream()
                    .filter(subnet -> subnet.mapPublicIpOnLaunch())
                    .findFirst()
                    .map(subnet -> subnet.subnetId())
                    .orElse(subnetResponse.subnets().get(0).subnetId());

        } catch (Exception e) {
            logger.error("Error finding default subnet: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Waits for an instance to be in a running state with proper exponential
     * backoff.
     * 
     * @param ec2        The EC2 client
     * @param instanceId The instance ID to wait for
     * @return The IP address of the instance
     * @throws Exception If the instance cannot be reached or no IP is available
     */
    private InetAddress waitForRunningInstanceWithExponentialBackoff(Ec2Client ec2, String instanceId)
            throws Exception {
        long waitTime = 2000;
        final long maxWaitTime = 300000;
        int attempts = 0;
        final int maxAttempts = 20;

        while (attempts < maxAttempts) {
            attempts++;
            try {
                DescribeInstancesRequest request = DescribeInstancesRequest.builder()
                        .instanceIds(instanceId)
                        .build();

                DescribeInstancesResponse response = ec2.describeInstances(request);
                if (!response.reservations().isEmpty() && !response.reservations().get(0).instances().isEmpty()) {
                    software.amazon.awssdk.services.ec2.model.Instance instance = response.reservations().get(0)
                            .instances().get(0);
                    InstanceState state = instance.state();

                    logger.info("Instance {} state: {}", instanceId, state.name());

                    if (state.code() == 16) { // Running
                        String ipAddress = instance.publicIpAddress();
                        if (ipAddress != null && !ipAddress.isEmpty()) {
                            try {
                                return InetAddress.getByName(ipAddress);
                            } catch (UnknownHostException e) {
                                logger.error("Failed to parse IP address", e);
                                throw new RuntimeException("Failed to parse IP address: " + e.getMessage());
                            }
                        }
                    } else if (state.code() == 48) { // Terminated
                        throw new RuntimeException(
                                "Instance was terminated before reaching running state: " + instanceId);
                    }
                }
            } catch (Ec2Exception e) {
                if (e.awsErrorDetails().errorCode().equals("InvalidInstanceID.NotFound")) {
                    logger.warn("Instance not found, waiting for AWS to propagate instance data: {}", instanceId);
                } else {
                    logger.warn("Error describing instance (attempt {}/{}): {}", attempts, maxAttempts, e.getMessage());
                }
            }

            // Exponential backoff
            Thread.sleep(waitTime);
            waitTime = Math.min(waitTime * 2, maxWaitTime);
        }

        throw new RuntimeException("Failed to get running instance with IP after " + maxAttempts + " attempts");
    }

    /**
     * Functional interface for retryable actions.
     */
    @FunctionalInterface
    private interface RetryableAction {
        boolean execute() throws Exception;
    }

    private Instance saveInstance(String name, String imageId, String size, String region,
            SSHKey sshKey, String instanceId, InetAddress ipAddress) {

        Provider provider = providerRepository.findById("AWS")
                .orElseGet(() -> providerRepository.save(new Provider("AWS")));

        // Get the default user for this image
        String defaultUser = getDefaultUserForImage(imageId);

        Instance instance = new Instance(provider, region, ipAddress);
        instance.setName(name);
        instance.setImageId(imageId);
        instance.setSize(size);
        instance.setStatus(Instance.InstanceStatus.CREATING);
        instance.setSshKey(sshKey);
        instance.setProviderId(instanceId);
        instance.setDefaultUser(defaultUser);

        return instanceRepository.save(instance);
    }

    @Override
    public void deleteInstance(String instanceId) {
        // First get the instance to determine its region
        try {
            Instance instance = null;
            // Find instance by providerId
            List<Instance> instances = instanceRepository.findAll().stream()
                    .filter(i -> instanceId.equals(i.getProviderId()))
                    .collect(Collectors.toList());

            if (!instances.isEmpty()) {
                instance = instances.get(0);
            }

            String region = (instance != null) ? instance.getRegion() : null;
            Ec2Client ec2 = getEc2Client(region);

            if (ec2 == null) {
                logger.warn("AWS credentials are not configured or EC2 client creation failed");
                return;
            }

            TerminateInstancesRequest request = TerminateInstancesRequest.builder()
                    .instanceIds(instanceId)
                    .build();

            ec2.terminateInstances(request);
            logger.info("AWS instance terminated: {} in region {}", instanceId, region);
        } catch (Exception e) {
            logger.error("Failed to delete AWS instance: {}", instanceId, e);
        }
    }

    @Override
    public InetAddress getInstanceIp(String instanceId) throws InstanceNotFoundException {
        // First get the instance to determine its region
        Instance instance = null;
        List<Instance> instances = instanceRepository.findAll().stream()
                .filter(i -> instanceId.equals(i.getProviderId()))
                .collect(Collectors.toList());

        if (!instances.isEmpty()) {
            instance = instances.get(0);
        } else {
            throw new InstanceNotFoundException("Instance not found in database: " + instanceId);
        }

        String region = instance.getRegion();
        Ec2Client ec2 = getEc2Client(region);

        if (ec2 == null) {
            logger.warn("AWS credentials are not configured or EC2 client creation failed");
            throw new InstanceNotFoundException("AWS client not configured");
        }

        try {
            DescribeInstancesRequest request = DescribeInstancesRequest.builder()
                    .instanceIds(instanceId)
                    .build();

            DescribeInstancesResponse response = ec2.describeInstances(request);

            if (response.reservations().isEmpty() ||
                    response.reservations().get(0).instances().isEmpty()) {
                throw new InstanceNotFoundException("Instance not found: " + instanceId);
            }

            String ipAddress = response.reservations().get(0).instances().get(0).publicIpAddress();

            if (ipAddress == null || ipAddress.isEmpty()) {
                throw new InstanceNotFoundException("Instance has no IP address: " + instanceId);
            }

            return InetAddress.getByName(ipAddress);
        } catch (UnknownHostException e) {
            logger.error("Failed to resolve IP address", e);
            throw new InstanceNotFoundException("Unable to resolve IP for instance: " + instanceId);
        } catch (Ec2Exception e) {
            logger.error("AWS service exception", e);
            throw new InstanceNotFoundException("Error retrieving instance: " + e.getMessage());
        }
    }

    @Override
    public List<com.tfg.infractory.infrastructure.cloud.model.Region> getAvailableRegions() {
        if (!isConfigured()) {
            logger.warn("AWS credentials are not configured. Returning cached regions or empty list.");
            return new ArrayList<>(cachedRegions);
        }

        if (cachedRegions.isEmpty()) {
            cachedRegions = fetchRegions();
        }

        return new ArrayList<>(cachedRegions);
    }

    private List<AWSRegion> fetchRegions() {
        Ec2Client ec2 = getEc2Client();
        if (ec2 == null) {
            return Collections.emptyList();
        }

        try {
            DescribeRegionsRequest request = DescribeRegionsRequest.builder().build();
            DescribeRegionsResponse response = ec2.describeRegions(request);

            return response.regions().stream()
                    .map(region -> new AWSRegion(region.regionName(), region.regionName()))
                    .collect(Collectors.toList());
        } catch (Exception e) {
            logger.error("Failed to get available regions", e);
            return Collections.emptyList();
        }
    }

    @Override
    public List<Size> getAvailableSizes() {
        updateDataIfNeeded();
        return new ArrayList<>(cachedSizes);
    }

    /**
     * Returns a list of instance sizes compatible with the given image ID
     * 
     * @param imageId The image ID to check compatibility for
     * @return List of compatible instance sizes
     */
    public List<Size> getCompatibleSizesForImage(String imageId) {
        updateDataIfNeeded();

        // If no imageId provided, return all sizes
        if (imageId == null || imageId.isEmpty()) {
            return getAvailableSizes();
        }

        // Clean the imageId
        String cleanedImageId = imageId;
        if (imageId.contains("[") || imageId.contains("]")) {
            cleanedImageId = imageId.replaceAll("[\\[\\]\\s]", "");
        }

        // Determine image architecture
        final String[] imageArch = { "x86_64" }; // Default to x86_64, use array for effectively final reference
        for (com.tfg.infractory.infrastructure.cloud.model.Image image : cachedImages) {
            if (image == null || image.getId() == null) {
                continue;
            }

            if (cleanedImageId.equals(image.getId().toString())) {
                // Check if it's an AWSImage with architecture info
                if (image instanceof com.tfg.infractory.infrastructure.cloud.model.aws.AWSImage) {
                    imageArch[0] = ((com.tfg.infractory.infrastructure.cloud.model.aws.AWSImage) image)
                            .getArchitecture();
                } else {
                    // Try to determine from description
                    String description = image.getDescription();
                    if (description != null &&
                            (description.toLowerCase().contains("arm") ||
                                    description.toLowerCase().contains("arm64") ||
                                    description.toLowerCase().contains("aarch64"))) {
                        imageArch[0] = "arm64";
                    }
                }
                break;
            }
        }

        // Filter sizes based on architecture
        return cachedSizes.stream()
                .filter(size -> {
                    String sizeArch = size.getArchitecture();
                    return sizeArch.equals(imageArch[0]);
                })
                .collect(Collectors.toList());
    }

    private List<AWSSize> fetchSizes() {
        List<AWSSize> sizes = new ArrayList<>();

        // Add t2 instances (all x86_64 architecture)
        sizes.add(new AWSSize("t2.micro", "t2.micro (1 vCPU, 1 GiB RAM) - Est. $8.00/month", 1, 1024, "x86_64"));
        sizes.add(new AWSSize("t2.small", "t2.small (1 vCPU, 2 GiB RAM) - Est. $18.00/month", 1, 2048, "x86_64"));
        sizes.add(new AWSSize("t2.medium", "t2.medium (2 vCPU, 4 GiB RAM) - Est. $32.00/month", 2, 4096, "x86_64"));
        sizes.add(new AWSSize("t2.large", "t2.large (2 vCPU, 8 GiB RAM) - Est. $60.00/month", 2, 8192, "x86_64"));

        // Add t3 instances (all x86_64 architecture)
        sizes.add(new AWSSize("t3.micro", "t3.micro (2 vCPU, 1 GiB RAM) - Est. $8.50/month", 2, 1024, "x86_64"));
        sizes.add(new AWSSize("t3.small", "t3.small (2 vCPU, 2 GiB RAM) - Est. $17.00/month", 2, 2048, "x86_64"));
        sizes.add(new AWSSize("t3.medium", "t3.medium (2 vCPU, 4 GiB RAM) - Est. $34.00/month", 2, 4096, "x86_64"));

        // Add m5 instances (all x86_64 architecture)
        sizes.add(new AWSSize("m5.large", "m5.large (2 vCPU, 8 GiB RAM) - Est. $80.00/month", 2, 8192, "x86_64"));
        sizes.add(new AWSSize("m5.xlarge", "m5.xlarge (4 vCPU, 16 GiB RAM) - Est. $150.00/month", 4, 16384, "x86_64"));

        // Add ARM-based instances
        sizes.add(new AWSSize("a1.medium", "a1.medium ARM (1 vCPU, 2 GiB RAM) - Est. $20.00/month", 1, 2048, "arm64"));
        sizes.add(new AWSSize("t4g.micro", "t4g.micro ARM (2 vCPU, 1 GiB RAM) - Est. $7.00/month", 2, 1024, "arm64"));
        sizes.add(new AWSSize("t4g.small", "t4g.small ARM (2 vCPU, 2 GiB RAM) - Est. $14.00/month", 2, 2048, "arm64"));
        sizes.add(
                new AWSSize("t4g.medium", "t4g.medium ARM (2 vCPU, 4 GiB RAM) - Est. $28.00/month", 2, 4096, "arm64"));

        // Sort by CPU architecture (x86_64 first, then arm64) and then by price
        Collections.sort(sizes, Comparator
                .<AWSSize, String>comparing(s -> s.getArchitecture())
                .thenComparing(s -> {
                    String id = s.getId();
                    if (id.contains("micro"))
                        return 1;
                    if (id.contains("small"))
                        return 2;
                    if (id.contains("medium"))
                        return 3;
                    if (id.contains("large"))
                        return 4;
                    if (id.contains("xlarge"))
                        return 5;
                    if (id.contains("2xlarge"))
                        return 6;
                    return 7;
                }));

        return sizes;
    }

    @Override
    public List<com.tfg.infractory.infrastructure.cloud.model.Image> getAllImages() {
        if (!isConfigured()) {
            logger.warn("AWS credentials are not configured. Returning cached images or empty list.");
            return new ArrayList<>(cachedImages);
        }

        if (cachedImages.isEmpty()) {
            // Default to eu-north-1 for fetching images if not specified
            cachedImages = fetchImages("eu-north-1");
        }

        return new ArrayList<>(cachedImages);
    }

    private List<com.tfg.infractory.infrastructure.cloud.model.Image> fetchImages(String regionName) {
        // Use the region-specific EC2 client
        Ec2Client ec2 = getEc2Client(regionName);
        if (ec2 == null) {
            return Collections.emptyList();
        }

        try {
            logger.info("Fetching AWS images for region: {}", regionName);
            List<com.tfg.infractory.infrastructure.cloud.model.Image> allImages = new ArrayList<>();

            // Fetch x86_64 images
            List<com.tfg.infractory.infrastructure.cloud.model.Image> x86Images = fetchImagesForArchitecture(ec2,
                    "x86_64", regionName);
            allImages.addAll(x86Images);

            // Fetch ARM64 images
            List<com.tfg.infractory.infrastructure.cloud.model.Image> armImages = fetchImagesForArchitecture(ec2,
                    "arm64", regionName);
            allImages.addAll(armImages);

            if (allImages.isEmpty()) {
                logger.warn("No images returned from AWS API for region {}. Using fallbacks.", regionName);
                // Add some fallback images for common distributions, specific to this region
                addFallbackImages(allImages, Collections.singletonList(regionName), regionName);
            }

            return allImages;
        } catch (Exception e) {
            logger.error("Error fetching AWS images for region {}: {}", regionName, e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    private List<com.tfg.infractory.infrastructure.cloud.model.Image> fetchImagesForArchitecture(Ec2Client ec2,
            String architecture, String regionName) {
        // Filter for free, public, available images with specified architecture
        Filter stateFilter = Filter.builder()
                .name("state")
                .values("available")
                .build();

        Filter architectureFilter = Filter.builder()
                .name("architecture")
                .values(architecture)
                .build();

        Filter platformFilter = Filter.builder()
                .name("platform-details")
                .values("Linux/UNIX")
                .build();

        // Only include images from trusted sources that don't require marketplace
        // subscription
        DescribeImagesRequest request = DescribeImagesRequest.builder()
                .filters(stateFilter, architectureFilter, platformFilter)
                .owners("amazon", "099720109477") // Amazon and Canonical (Ubuntu)
                .build();

        logger.info("Fetching AWS images for architecture {} with request: {}", architecture, request);
        DescribeImagesResponse response = ec2.describeImages(request);
        List<com.tfg.infractory.infrastructure.cloud.model.Image> images = new ArrayList<>();

        logger.info("Received {} AWS images for architecture {}", response.images().size(), architecture);

        // Process the images if we have any
        if (!response.images().isEmpty()) {
            List<software.amazon.awssdk.services.ec2.model.Image> sortedImages = response.images().stream()
                    .filter(img -> img.name() != null && !img.name().isEmpty())
                    .filter(img -> img.imageId() != null && img.imageId().startsWith("ami-")) // Ensure valid AMI IDs
                    .filter(img -> {
                        // Exclude marketplace images that require subscription
                        if (img.description() != null &&
                                (img.description().contains("marketplace") ||
                                        img.description().contains("Marketplace"))) {
                            return false;
                        }

                        // Filter for common Linux distributions
                        String name = img.name().toLowerCase();
                        return (name.contains("ubuntu") ||
                                name.contains("amazon") ||
                                name.contains("linux") ||
                                name.contains("debian") ||
                                name.contains("centos")) &&
                        // Exclude images with "BETA", "Preview" or "Test" in the name
                                !name.contains("beta") &&
                                !name.contains("preview") &&
                                !name.contains("test");
                    })
                    .sorted((img1, img2) -> {
                        if (img1.creationDate() == null)
                            return 1;
                        if (img2.creationDate() == null)
                            return -1;
                        return img2.creationDate().compareTo(img1.creationDate());
                    })
                    .collect(Collectors.toList());

            for (software.amazon.awssdk.services.ec2.model.Image awsImage : sortedImages) {
                // Skip images with null or invalid IDs
                if (awsImage.imageId() == null || !awsImage.imageId().startsWith("ami-")) {
                    logger.warn("Skipping AWS image with invalid ID: {}", awsImage.imageId());
                    continue;
                }

                // Parse creation date if available, or use current date as fallback
                Date createdAt = new Date();
                if (awsImage.creationDate() != null && !awsImage.creationDate().isEmpty()) {
                    try {
                        Instant instant = Instant.parse(awsImage.creationDate());
                        createdAt = Date.from(instant);
                    } catch (Exception e) {
                        logger.warn("Failed to parse AWS image creation date: {}", awsImage.creationDate(), e);
                    }
                }

                String imageName = awsImage.name();
                String description = String.format("%s (%s) - %s",
                        imageName,
                        architecture,
                        awsImage.description() != null ? awsImage.description() : "No description");

                logger.info("Adding AWS image with ID: {}, name: {}", awsImage.imageId(), imageName);

                com.tfg.infractory.infrastructure.cloud.model.Image image = new com.tfg.infractory.infrastructure.cloud.model.aws.AWSImage(
                        awsImage.imageId(),
                        imageName,
                        description,
                        createdAt,
                        Collections.singletonList(regionName),
                        architecture);

                images.add(image);
            }
        }

        return images;
    }

    @Override
    public List<com.tfg.infractory.infrastructure.cloud.model.Image> getImagesForRegion(String regionSlug) {
        if (!isConfigured()) {
            logger.warn("AWS credentials are not configured. Returning cached images or empty list.");
            return new ArrayList<>(cachedImages);
        }

        String region = (regionSlug != null && !regionSlug.isEmpty()) ? regionSlug : "eu-north-1";
        logger.info("Fetching images for AWS region: {}", region);

        return fetchImages(region);
    }

    @Override
    public boolean isConfigured() {
        return awsAccessKey != null && !awsAccessKey.isEmpty() &&
                awsSecretKey != null && !awsSecretKey.isEmpty() &&
                awsRegion != null && !awsRegion.isEmpty();
    }

    @Override
    public Instance.InstanceStatus getInstanceStatus(String instanceId) throws InstanceNotFoundException {
        // Get the instance to determine its region
        Instance instance = null;
        List<Instance> instances = instanceRepository.findAll().stream()
                .filter(i -> instanceId.equals(i.getProviderId()))
                .collect(Collectors.toList());

        if (!instances.isEmpty()) {
            instance = instances.get(0);
        } else {
            throw new InstanceNotFoundException("Instance not found in database: " + instanceId);
        }

        String region = instance.getRegion();
        Ec2Client ec2 = getEc2Client(region);

        if (ec2 == null) {
            logger.warn("AWS credentials are not configured or EC2 client creation failed");
            return Instance.InstanceStatus.ERROR;
        }

        try {
            DescribeInstancesRequest request = DescribeInstancesRequest.builder()
                    .instanceIds(instanceId)
                    .build();

            DescribeInstancesResponse response = ec2.describeInstances(request);

            if (response.reservations().isEmpty() ||
                    response.reservations().get(0).instances().isEmpty()) {
                logger.warn("No instance found with ID: {}", instanceId);
                return Instance.InstanceStatus.ERROR;
            }

            software.amazon.awssdk.services.ec2.model.Instance awsInstance = response.reservations().get(0).instances()
                    .get(0);
            InstanceState state = awsInstance.state();

            if (state == null) {
                logger.warn("Instance state is null for instance: {}", instanceId);
                return Instance.InstanceStatus.ERROR;
            }

            // Map AWS instance state code to our own status enum
            switch (state.code()) {
                case 0:
                    return Instance.InstanceStatus.CREATING;
                case 16:
                    return Instance.InstanceStatus.RUNNING;
                case 32:
                case 64:
                    return Instance.InstanceStatus.STOPPED;
                case 48:
                    return Instance.InstanceStatus.DELETED;
                case 80:
                    return Instance.InstanceStatus.STOPPED;
                default:
                    logger.warn("Unknown instance state code: {} for instance: {}", state.code(), instanceId);
                    return Instance.InstanceStatus.ERROR;
            }
        } catch (Ec2Exception e) {
            if (e.awsErrorDetails().errorCode().equals("InvalidInstanceID.NotFound")) {
                throw new InstanceNotFoundException("Instance not found: " + instanceId);
            }
            logger.error("Error getting instance status for {}: {}", instanceId, e.getMessage());
            return Instance.InstanceStatus.ERROR;
        }
    }

    /**
     * Uploads an SSH key to AWS EC2 if it doesn't already exist.
     * 
     * @param ec2    The EC2 client to use
     * @param sshKey The SSH key to upload
     * @return The key name if successful, null otherwise
     */
    private String uploadSshKeyIfNeeded(Ec2Client ec2, SSHKey sshKey) {
        if (sshKey == null || sshKey.getPublicKey() == null || sshKey.getPublicKey().isEmpty()) {
            logger.warn("Cannot upload SSH key: key is null or invalid");
            return null;
        }

        // Use the key name provided by the user, but ensure it's AWS-compatible
        String keyName = sanitizeKeyName(sshKey.getName());

        try {
            // Check if the key already exists in AWS
            if (sshKeyExistsInAws(ec2, keyName)) {
                logger.info("SSH key '{}' already exists in AWS, will use existing key", keyName);
                return keyName;
            }

            // If not, import it
            logger.info("Importing SSH key '{}' to AWS", keyName);
            ImportKeyPairRequest request = ImportKeyPairRequest.builder()
                    .keyName(keyName)
                    .publicKeyMaterial(SdkBytes.fromByteArray(sshKey.getPublicKey().getBytes()))
                    .build();

            ImportKeyPairResponse response = ec2.importKeyPair(request);

            if (response.keyName() != null && !response.keyName().isEmpty()) {
                logger.info("Successfully imported SSH key: {}", response.keyName());
                return response.keyName();
            } else {
                logger.warn("Failed to import SSH key: empty response name");
                return null;
            }
        } catch (Ec2Exception e) {
            logger.error("Error uploading SSH key to AWS: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Checks if an SSH key with the given name exists in AWS.
     * 
     * @param ec2     The EC2 client to use
     * @param keyName The key name to check
     * @return True if the key exists, false otherwise
     */
    private boolean sshKeyExistsInAws(Ec2Client ec2, String keyName) {
        try {
            DescribeKeyPairsRequest request = DescribeKeyPairsRequest.builder()
                    .keyNames(keyName)
                    .build();

            // If this succeeds, the key exists
            ec2.describeKeyPairs(request);
            return true;
        } catch (Ec2Exception e) {
            // If we get a InvalidKeyPair.NotFound exception, the key doesn't exist
            if (e.awsErrorDetails().errorCode().equals("InvalidKeyPair.NotFound")) {
                return false;
            }
            // For other exceptions, log and assume key doesn't exist
            logger.warn("Error checking if key exists: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Sanitizes an SSH key name to be compatible with AWS requirements.
     * AWS key names can only include alphanumeric characters, underscores and
     * hyphens.
     * 
     * @param keyName The original key name
     * @return A sanitized key name
     */
    private String sanitizeKeyName(String keyName) {
        if (keyName == null || keyName.isEmpty()) {
            return "default-key-" + System.currentTimeMillis();
        }

        // Replace spaces and special characters with hyphens
        String sanitized = keyName.replaceAll("[^a-zA-Z0-9_\\-]", "-");

        // Ensure the key name isn't too long (AWS has a 255 character limit)
        if (sanitized.length() > 250) {
            sanitized = sanitized.substring(0, 250);
        }

        return sanitized;
    }

    /**
     * Deletes an SSH key from AWS EC2.
     * 
     * @param keyName The name of the key to delete
     */
    public void deleteSshKeyFromAws(String keyName) {
        Ec2Client ec2 = getEc2Client();
        if (ec2 == null) {
            logger.warn("AWS credentials are not configured or EC2 client creation failed");
            return;
        }

        try {
            DeleteKeyPairRequest request = DeleteKeyPairRequest.builder()
                    .keyName(keyName)
                    .build();

            ec2.deleteKeyPair(request);
            logger.info("Successfully deleted SSH key '{}' from AWS", keyName);
        } catch (Ec2Exception e) {
            logger.error("Error deleting SSH key from AWS: {}", e.getMessage(), e);
        }
    }

    public boolean validateArchitectureCompatibility(String imageId, String instanceType) {
        // Check if the instance type is ARM-based (Graviton)
        boolean isArmInstance = instanceType.contains("graviton") ||
                instanceType.startsWith("a1.") ||
                instanceType.startsWith("t4g.") ||
                instanceType.startsWith("c6g.") ||
                instanceType.startsWith("m6g.") ||
                instanceType.startsWith("r6g.");

        // Find image architecture from description
        boolean isArmImage = false;

        // Clean the imageId by removing any square brackets
        String cleanedImageId = imageId;
        if (imageId.contains("[") || imageId.contains("]")) {
            cleanedImageId = imageId.replaceAll("[\\[\\]\\s]", "");
        }

        // Handle the case when cachedImages is null or empty
        if (cachedImages == null || cachedImages.isEmpty()) {
            logger.warn("No cached images available to check architecture compatibility");
            return true; // Allow the operation to proceed since we can't verify
        }

        // Find the image in the current cached images
        for (com.tfg.infractory.infrastructure.cloud.model.Image image : cachedImages) {
            // Check if the image has a valid ID before comparing
            if (image == null || image.getId() == null) {
                continue;
            }

            // Compare as strings to avoid type issues
            if (cleanedImageId.equals(image.getId().toString())) {
                String description = image.getDescription();
                if (description != null) {
                    isArmImage = description.toLowerCase().contains("arm") ||
                            description.toLowerCase().contains("arm64") ||
                            description.toLowerCase().contains("aarch64");
                }
                break;
            }
        }

        // Check compatibility
        if (isArmInstance && !isArmImage) {
            logger.warn("Architecture mismatch: Instance {} is ARM-based but selected image appears to be x86_64",
                    instanceType);
            return false;
        } else if (!isArmInstance && isArmImage) {
            logger.warn("Architecture mismatch: Instance {} is x86_64-based but selected image appears to be ARM64",
                    instanceType);
            return false;
        }

        return true;
    }

    /**
     * Get the default username for an AWS image based on its ID or name.
     * 
     * @param imageId The AWS image ID
     * @return The default user for the image
     */
    private String getDefaultUserForImage(String imageId) {
        if (imageId == null) {
            logger.warn("Image ID is null, defaulting to 'ec2-user' for SSH access");
            return "ec2-user"; // Default to ec2-user as fallback
        }

        // Clean the imageId by removing any square brackets or surrounding whitespace
        String cleanedImageId = imageId;
        if (imageId.contains("[") || imageId.contains("]")) {
            cleanedImageId = imageId.replaceAll("[\\[\\]\\s]", "");
        }

        // Normalize image ID for comparison
        String id = cleanedImageId.toLowerCase();
        logger.debug("Determining default user for image ID: {}", id);

        // Check if image ID matches any known pattern for distribution identification
        if (id.contains("ubuntu")) {
            logger.info("Detected Ubuntu image: {}, using 'ubuntu' as default user", id);
            return "ubuntu";
        } else if (id.contains("debian")) {
            logger.info("Detected Debian image: {}, using 'admin' as default user", id);
            return "admin";
        } else if (id.contains("centos")) {
            logger.info("Detected CentOS image: {}, using 'centos' as default user", id);
            return "centos";
        } else if (id.contains("fedora")) {
            logger.info("Detected Fedora image: {}, using 'fedora' as default user", id);
            return "fedora";
        } else if (id.contains("rhel") || id.contains("redhat")) {
            logger.info("Detected RHEL image: {}, using 'ec2-user' as default user", id);
            return "ec2-user";
        } else if (id.contains("suse") || id.contains("sles")) {
            logger.info("Detected SUSE image: {}, using 'ec2-user' as default user", id);
            return "ec2-user";
        } else if (id.contains("bitnami")) {
            logger.info("Detected Bitnami image: {}, using 'bitnami' as default user", id);
            return "bitnami";
        } else if (id.contains("amzn") || id.contains("amazon")) {
            logger.info("Detected Amazon Linux image: {}, using 'ec2-user' as default user", id);
            return "ec2-user";
        }

        // Check for cached image metadata (may contain distribution info in
        // description)
        for (com.tfg.infractory.infrastructure.cloud.model.Image image : cachedImages) {
            if (image != null && image.getId() != null &&
                    image.getId().toString().equals(cleanedImageId)) {

                String description = image.getDescription();
                if (description != null) {
                    description = description.toLowerCase();
                    if (description.contains("ubuntu")) {
                        logger.info("Detected Ubuntu image from metadata description, using 'ubuntu' as default user");
                        return "ubuntu";
                    } else if (description.contains("debian")) {
                        logger.info("Detected Debian image from metadata description, using 'admin' as default user");
                        return "admin";
                    } else if (description.contains("centos")) {
                        logger.info("Detected CentOS image from metadata description, using 'centos' as default user");
                        return "centos";
                    } else if (description.contains("amazon") || description.contains("linux")) {
                        logger.info(
                                "Detected Amazon Linux from metadata description, using 'ec2-user' as default user");
                        return "ec2-user";
                    }
                }

                // Check name as well
                String name = image.getName();
                if (name != null) {
                    name = name.toLowerCase();
                    if (name.contains("ubuntu")) {
                        logger.info("Detected Ubuntu image from metadata name, using 'ubuntu' as default user");
                        return "ubuntu";
                    }
                }
            }
        }

        // Default to ec2-user if we can't determine the user
        logger.info("Could not determine distribution for image ID: {}. Using 'ec2-user' as default.", imageId);
        return "ec2-user";
    }

    /**
     * Creates a new security group or returns an existing one that allows SSH
     * access.
     *
     * @param ec2       The EC2 client
     * @param groupName The name for the security group
     * @return The security group ID or null if creation failed
     */
    private String createOrGetSecurityGroup(Ec2Client ec2, String groupName) {
        try {
            // First check if security group already exists
            DescribeSecurityGroupsRequest describeRequest = DescribeSecurityGroupsRequest.builder()
                    .filters(
                            Filter.builder()
                                    .name("group-name")
                                    .values(groupName)
                                    .build())
                    .build();

            DescribeSecurityGroupsResponse describeResponse = ec2.describeSecurityGroups(describeRequest);
            if (!describeResponse.securityGroups().isEmpty()) {
                String existingGroupId = describeResponse.securityGroups().get(0).groupId();
                logger.info("Using existing security group: {}", existingGroupId);

                // Make sure the security group has all the necessary rules
                ensureSecurityGroupRules(ec2, existingGroupId);
                return existingGroupId;
            }

            // Find default VPC
            DescribeVpcsRequest vpcRequest = DescribeVpcsRequest.builder()
                    .filters(
                            Filter.builder().name("isDefault").values("true").build())
                    .build();

            DescribeVpcsResponse vpcResponse = ec2.describeVpcs(vpcRequest);
            if (vpcResponse.vpcs().isEmpty()) {
                logger.error("No default VPC found for security group creation");
                return null;
            }

            String vpcId = vpcResponse.vpcs().get(0).vpcId();

            // Create a new security group
            CreateSecurityGroupRequest createRequest = CreateSecurityGroupRequest.builder()
                    .groupName(groupName)
                    .description("Security group for Infractory SSH access and ping")
                    .vpcId(vpcId) // Explicitly set VPC ID
                    .build();

            CreateSecurityGroupResponse createResponse = ec2.createSecurityGroup(createRequest);
            String securityGroupId = createResponse.groupId();
            logger.info("Created new security group: {}", securityGroupId);

            // Wait for the security group to be available
            Thread.sleep(1000);

            // Add security group rules
            ensureSecurityGroupRules(ec2, securityGroupId);

            return securityGroupId;
        } catch (Exception e) {
            logger.error("Failed to create or get security group: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Ensures that a security group has all the necessary rules for SSH and ping.
     * 
     * @param ec2             The EC2 client
     * @param securityGroupId The security group ID
     */
    private void ensureSecurityGroupRules(Ec2Client ec2, String securityGroupId) {
        try {
            logger.info("Setting up permissive security group rules for instance deployment: {}", securityGroupId);

            // Allow all TCP traffic from anywhere (instead of just SSH)
            IpPermission allTcpPermission = IpPermission.builder()
                    .ipProtocol("tcp")
                    .fromPort(0) // All TCP ports
                    .toPort(65535)
                    .ipRanges(
                            IpRange.builder()
                                    .cidrIp("0.0.0.0/0")
                                    .description("Allow all TCP traffic from anywhere")
                                    .build())
                    .build();

            // Allow all UDP traffic from anywhere (for Nebula and other services)
            IpPermission allUdpPermission = IpPermission.builder()
                    .ipProtocol("udp")
                    .fromPort(0) // All UDP ports
                    .toPort(65535)
                    .ipRanges(
                            IpRange.builder()
                                    .cidrIp("0.0.0.0/0")
                                    .description("Allow all UDP traffic from anywhere")
                                    .build())
                    .build();

            // Add ICMP (ping) ingress rule
            IpPermission pingPermission = IpPermission.builder()
                    .ipProtocol("icmp")
                    .fromPort(-1)
                    .toPort(-1)
                    .ipRanges(
                            IpRange.builder()
                                    .cidrIp("0.0.0.0/0")
                                    .description("Allow ping from anywhere")
                                    .build())
                    .build();

            // Authorize all the rules
            AuthorizeSecurityGroupIngressRequest ingressRequest = AuthorizeSecurityGroupIngressRequest.builder()
                    .groupId(securityGroupId)
                    .ipPermissions(allTcpPermission, allUdpPermission, pingPermission)
                    .build();

            try {
                ec2.authorizeSecurityGroupIngress(ingressRequest);
                logger.info("Added permissive ingress rules to security group: {}", securityGroupId);
            } catch (Ec2Exception e) {
                if (e.awsErrorDetails().errorCode().equals("InvalidPermission.Duplicate")) {
                    logger.info("Security group already has some of the required ingress rules: {}", securityGroupId);

                    // Try adding rules individually in case some but not all exist
                    try {
                        ec2.authorizeSecurityGroupIngress(AuthorizeSecurityGroupIngressRequest.builder()
                                .groupId(securityGroupId)
                                .ipPermissions(allTcpPermission)
                                .build());
                        logger.info("Added TCP ingress rule to security group: {}", securityGroupId);
                    } catch (Ec2Exception e2) {
                        if (!e2.awsErrorDetails().errorCode().equals("InvalidPermission.Duplicate")) {
                            logger.warn("Failed to add TCP rule: {}", e2.getMessage());
                        }
                    }

                    try {
                        ec2.authorizeSecurityGroupIngress(AuthorizeSecurityGroupIngressRequest.builder()
                                .groupId(securityGroupId)
                                .ipPermissions(allUdpPermission)
                                .build());
                        logger.info("Added UDP ingress rule to security group: {}", securityGroupId);
                    } catch (Ec2Exception e2) {
                        if (!e2.awsErrorDetails().errorCode().equals("InvalidPermission.Duplicate")) {
                            logger.warn("Failed to add UDP rule: {}", e2.getMessage());
                        }
                    }

                    try {
                        ec2.authorizeSecurityGroupIngress(AuthorizeSecurityGroupIngressRequest.builder()
                                .groupId(securityGroupId)
                                .ipPermissions(pingPermission)
                                .build());
                        logger.info("Added ICMP ingress rule to security group: {}", securityGroupId);
                    } catch (Ec2Exception e2) {
                        if (!e2.awsErrorDetails().errorCode().equals("InvalidPermission.Duplicate")) {
                            logger.warn("Failed to add ICMP rule: {}", e2.getMessage());
                        }
                    }
                } else {
                    throw e;
                }
            }

            // Add egress rule for all traffic
            IpPermission allTrafficPermission = IpPermission.builder()
                    .ipProtocol("-1") // All protocols
                    .fromPort(-1)
                    .toPort(-1)
                    .ipRanges(
                            IpRange.builder()
                                    .cidrIp("0.0.0.0/0")
                                    .description("Allow all outbound traffic")
                                    .build())
                    .build();

            AuthorizeSecurityGroupEgressRequest egressRequest = AuthorizeSecurityGroupEgressRequest.builder()
                    .groupId(securityGroupId)
                    .ipPermissions(allTrafficPermission)
                    .build();

            try {
                ec2.authorizeSecurityGroupEgress(egressRequest);
                logger.info("Added egress rule for all traffic to security group: {}", securityGroupId);
            } catch (Ec2Exception e) {
                if (e.awsErrorDetails().errorCode().equals("InvalidPermission.Duplicate")) {
                    logger.info("Security group already has the required egress rules: {}", securityGroupId);
                } else {
                    throw e;
                }
            }
        } catch (Exception e) {
            logger.error("Failed to configure security group rules: {}", e.getMessage(), e);
        }
    }

    // Add fallback images for a specific region
    private void addFallbackImages(List<com.tfg.infractory.infrastructure.cloud.model.Image> images,
            List<String> regions, String regionName) {
        // Use region-specific AMI IDs for fallback images
        String amazonLinuxAmiId;
        String ubuntuAmiId;

        // Map of region -> Amazon Linux 2023 AMI ID
        switch (regionName) {
            case "eu-north-1": // Stockholm
                amazonLinuxAmiId = "ami-0d441f5643da997cb";
                ubuntuAmiId = "ami-0989fb15ce71ba39e";
                break;
            case "eu-west-1": // Ireland
                amazonLinuxAmiId = "ami-0694d931cee5805bd";
                ubuntuAmiId = "ami-0905a3c97561e0b69";
                break;
            case "eu-central-1": // Frankfurt
                amazonLinuxAmiId = "ami-06dd92ecc78f9b0e6";
                ubuntuAmiId = "ami-0faab6bdbac9486fb";
                break;
            case "us-east-1": // Virginia
                amazonLinuxAmiId = "ami-0889a44b331db0194";
                ubuntuAmiId = "ami-0e83be366243f524a";
                break;
            case "us-west-1": // California
                amazonLinuxAmiId = "ami-0a0409af1cb831414";
                ubuntuAmiId = "ami-0ce2cb35386079f1a";
                break;
            case "us-west-2": // Oregon
                amazonLinuxAmiId = "ami-00448a337adc93c05";
                ubuntuAmiId = "ami-03f65b8614a860c29";
                break;
            case "ap-southeast-1": // Singapore
                amazonLinuxAmiId = "ami-0dc5785603ad4ff54";
                ubuntuAmiId = "ami-078c1149d8ad719a7";
                break;
            case "ap-northeast-1": // Tokyo
                amazonLinuxAmiId = "ami-03dceaabddff8d9e7";
                ubuntuAmiId = "ami-0d52744dc3e268745";
                break;
            case "ap-southeast-2": // Sydney
                amazonLinuxAmiId = "ami-0c5d6ca774146a472";
                ubuntuAmiId = "ami-0310483fb2b488153";
                break;
            default:
                // Default to eu-north-1 AMIs if region not specifically defined
                amazonLinuxAmiId = "ami-0d441f5643da997cb";
                ubuntuAmiId = "ami-0989fb15ce71ba39e";
        }

        logger.info("Adding fallback AMIs for region: {} - Amazon Linux: {}, Ubuntu: {}",
                regionName, amazonLinuxAmiId, ubuntuAmiId);

        // Check if the AMI IDs are valid
        if (amazonLinuxAmiId == null || !amazonLinuxAmiId.startsWith("ami-") ||
                ubuntuAmiId == null || !ubuntuAmiId.startsWith("ami-")) {
            logger.warn("Invalid AMI IDs detected for fallback images: amazonLinux={}, ubuntu={}",
                    amazonLinuxAmiId, ubuntuAmiId);
        }

        // Amazon Linux 2023 AMI for the specified region
        images.add(new com.tfg.infractory.infrastructure.cloud.model.aws.AWSImage(
                amazonLinuxAmiId,
                "Amazon Linux 2023 AMI",
                "Amazon Linux 2023 AMI (x86_64) - Region: " + regionName,
                new Date(),
                regions,
                "x86_64"));

        // Ubuntu 22.04 LTS AMI for the specified region
        images.add(new com.tfg.infractory.infrastructure.cloud.model.aws.AWSImage(
                ubuntuAmiId,
                "Ubuntu Server 22.04 LTS",
                "Canonical, Ubuntu, 22.04 LTS (x86_64) - Region: " + regionName,
                new Date(),
                regions,
                "x86_64"));

        logger.info("Added {} fallback images for region {}", 2, regionName);
    }

    /**
     * Validates that the selected instance type is available in the specified
     * region
     * 
     * @param region       The AWS region
     * @param instanceType The instance type to check
     * @return true if the instance type is available in the region, false otherwise
     */
    public boolean validateRegionInstanceTypeCompatibility(String region, String instanceType) {
        try {
            Ec2Client ec2 = getEc2Client(region);
            if (ec2 == null) {
                logger.warn("EC2 client not available for region {}", region);
                return false;
            }

            // Check if the instance type is available in the region using
            // DescribeInstanceTypeOfferings
            DescribeInstanceTypeOfferingsRequest request = DescribeInstanceTypeOfferingsRequest.builder()
                    .locationType("region")
                    .filters(
                            Filter.builder()
                                    .name("instance-type")
                                    .values(instanceType)
                                    .build(),
                            Filter.builder()
                                    .name("location")
                                    .values(region)
                                    .build())
                    .build();

            DescribeInstanceTypeOfferingsResponse response = ec2.describeInstanceTypeOfferings(request);
            boolean isAvailable = !response.instanceTypeOfferings().isEmpty();

            if (!isAvailable) {
                logger.warn("Instance type {} is not available in region {}", instanceType, region);
            } else {
                logger.info("Instance type {} is available in region {}", instanceType, region);
            }

            return isAvailable;
        } catch (Exception e) {
            logger.error("Error checking instance type availability in region: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Returns a list of instance sizes compatible with the given image ID and
     * available in the specified region
     * 
     * @param imageId The image ID to check compatibility for
     * @param region  The AWS region to check availability in
     * @return List of compatible and available instance sizes
     */
    public List<Size> getRegionCompatibleSizesForImage(String imageId, String region) {
        updateDataIfNeeded();

        // First get sizes that are architecture-compatible
        List<Size> architectureCompatibleSizes = getCompatibleSizesForImage(imageId);

        // Then filter for region availability
        if (region == null || region.isEmpty()) {
            logger.warn("No region specified for checking instance type availability");
            return architectureCompatibleSizes;
        }

        // Create EC2 client for the specified region
        Ec2Client ec2 = getEc2Client(region);
        if (ec2 == null) {
            logger.warn("Failed to create EC2 client for region {}", region);
            return architectureCompatibleSizes;
        }

        try {
            // Get all instance types available in the region
            DescribeInstanceTypeOfferingsRequest request = DescribeInstanceTypeOfferingsRequest.builder()
                    .locationType("region")
                    .filters(
                            Filter.builder()
                                    .name("location")
                                    .values(region)
                                    .build())
                    .build();

            DescribeInstanceTypeOfferingsResponse response = ec2.describeInstanceTypeOfferings(request);
            Set<String> availableTypes = response.instanceTypeOfferings().stream()
                    .map(offering -> offering.instanceType().toString())
                    .collect(Collectors.toSet());

            logger.info("Found {} instance types available in region {}", availableTypes.size(), region);

            // Filter the architecture-compatible sizes to only include those available in
            // the region
            List<Size> compatibleSizes = architectureCompatibleSizes.stream()
                    .filter(size -> availableTypes.contains(size.getId()))
                    .collect(Collectors.toList());

            logger.info("Filtered down to {} compatible sizes for image {} in region {}",
                    compatibleSizes.size(), imageId, region);

            return compatibleSizes;

        } catch (Exception e) {
            logger.error("Error checking instance type availability in region {}: {}", region, e.getMessage(), e);
            return architectureCompatibleSizes; // Return the architecture-compatible list if we can't check region
                                                // availability
        }
    }
}
