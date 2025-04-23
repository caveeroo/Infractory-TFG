package com.tfg.infractory.infrastructure.local;

import java.util.Date;
import java.util.List;
import org.slf4j.Logger;
import java.io.Closeable;
import java.util.ArrayList;
import java.net.InetAddress;
import org.slf4j.LoggerFactory;
import java.util.concurrent.TimeUnit;
import java.net.UnknownHostException;
import java.util.concurrent.CountDownLatch;
import com.github.dockerjava.api.model.Frame;
import org.springframework.stereotype.Service;
import org.springframework.context.annotation.Lazy;
import com.github.dockerjava.api.async.ResultCallback;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.beans.factory.annotation.Autowired;

import com.github.dockerjava.api.model.Ports;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.model.Capability;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.ContainerNetwork;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.PullImageResultCallback;
import com.github.dockerjava.api.command.InspectContainerResponse;

import com.tfg.infractory.infrastructure.docker.service.DockerSwarmService;
import com.tfg.infractory.web.event.DockerInstalledEvent;
import com.tfg.infractory.domain.exception.InstanceNotFoundException;
import com.tfg.infractory.domain.model.Instance;
import com.tfg.infractory.domain.model.Provider;
import com.tfg.infractory.domain.repository.InstanceRepository;
import com.tfg.infractory.domain.repository.ProviderRepository;
import com.tfg.infractory.infrastructure.cloud.model.Image;
import com.tfg.infractory.infrastructure.cloud.model.Region;
import com.tfg.infractory.infrastructure.cloud.model.Size;
import com.tfg.infractory.infrastructure.cloud.service.CloudProviderService;
import com.tfg.infractory.infrastructure.ssh.model.SSHKey;
import com.tfg.infractory.infrastructure.ssh.service.SSHKeyService;
import com.tfg.infractory.domain.model.Server;
import com.tfg.infractory.domain.repository.ServerRepository;

@Service("Local")
public class LocalProviderService implements CloudProviderService {

    private static final Logger logger = LoggerFactory.getLogger(LocalProviderService.class);

    private final DockerClient dockerClient;
    private final InstanceRepository instanceRepository;
    private final ProviderRepository providerRepository;
    private final DockerSwarmService dockerSwarmService;
    private final ApplicationEventPublisher eventPublisher;
    private final ServerRepository serverRepository;

    @Autowired
    public LocalProviderService(InstanceRepository instanceRepository, ProviderRepository providerRepository,
            SSHKeyService sshKeyService, DockerClient dockerClient, @Lazy DockerSwarmService dockerSwarmService,
            ApplicationEventPublisher eventPublisher, ServerRepository serverRepository) {
        this.instanceRepository = instanceRepository;
        this.providerRepository = providerRepository;
        this.dockerClient = dockerClient;
        this.dockerSwarmService = dockerSwarmService;
        this.eventPublisher = eventPublisher;
        this.serverRepository = serverRepository;
    }

    @Override
    public Instance createInstance(String name, String imageId, String size, String region, SSHKey sshKey) {
        try {
            logger.info("Creating local instance: name={}, imageId={}, size={}, region={}", name, imageId, size,
                    region);

            imageId = validateAndPullImage(imageId);
            String cmd = buildContainerCommand(sshKey);

            CreateContainerResponse container = createContainer(name, imageId, cmd);
            String containerId = container.getId();
            logger.info("Container created with ID: {}", containerId);

            dockerClient.startContainerCmd(containerId).exec();
            logger.info("Container started successfully");

            validateContainerRunning(containerId);

            ContainerInfo containerInfo = getContainerInfo(containerId);

            Provider provider = getOrCreateProvider();
            Instance instance = createInstanceObject(name, imageId, size, containerInfo, provider, sshKey);

            Instance savedInstance = instanceRepository.save(instance);
            logger.info("Instance saved to database: {}", savedInstance);

            // Install Docker
            String installResult = dockerSwarmService.installDockerInContainer(instance, sshKey);
            logger.info("Docker installation result: {}", installResult);

            // Update instance status to RUNNING after Docker installation
            savedInstance.setStatus(Instance.InstanceStatus.RUNNING);
            savedInstance = instanceRepository.save(savedInstance);
            logger.info("Instance status updated to RUNNING after Docker installation");

            // Wait a bit for the server to be created and saved
            Thread.sleep(1000);

            // Check if server exists before publishing event
            Server server = serverRepository.findByInstance(savedInstance);
            if (server != null) {
                // Publish event for Docker installation completion
                eventPublisher.publishEvent(new DockerInstalledEvent(this, savedInstance, sshKey));
                logger.info("Published DockerInstalledEvent for instance: {}", savedInstance.getId());
            } else {
                logger.info("Skipping DockerInstalledEvent - server not yet created for instance: {}",
                        savedInstance.getId());
            }

            return savedInstance;
        } catch (Exception e) {
            logger.error("Failed to create local instance", e);
            throw new RuntimeException("Failed to create local instance: " + e.getMessage(), e);
        }
    }

    public String initializeDockerSwarmOnHost(Instance instance) {
        try {
            logger.info("Initializing Docker Swarm on host machine for local instance: {}", instance.getId());

            // Check if the instance has a server and if that server has Nebula configured
            Server server = serverRepository.findByInstance(instance);
            if (server == null || server.getVpn() == null) {
                logger.info("Instance {} does not have Nebula configured yet. Skipping swarm initialization.",
                        instance.getId());
                return "Skipping swarm initialization: Waiting for Nebula configuration";
            }

            // Initialize or join swarm only after Nebula is configured
            String swarmResult = dockerSwarmService.initializeDockerAndJoinSwarm(instance, instance.getSshKey());
            logger.info("Swarm initialization result: {}", swarmResult);
            return swarmResult;
        } catch (Exception e) {
            logger.error("Error initializing Docker Swarm on host", e);
            return "Error initializing Docker Swarm: " + e.getMessage();
        }
    }

    @Override
    public void deleteInstance(String instanceId) {
        try {
            logger.info("Deleting local instance: {}", instanceId);

            // Remove the instance from the Swarm (if it was part of it)
            try {
                String leaveResult = dockerSwarmService.leaveSwarm();
                logger.info("Instance left Swarm. Result: {}", leaveResult);
            } catch (Exception e) {
                logger.warn("Error while leaving Swarm for instance: {}. Error: {}", instanceId, e.getMessage());
                // Continue with deletion even if leaving Swarm fails
            }

            // Stop and remove the container
            dockerClient.stopContainerCmd(instanceId).exec();
            dockerClient.removeContainerCmd(instanceId).exec();

            logger.info("Local instance deleted successfully: {}", instanceId);
        } catch (Exception e) {
            logger.error("Failed to delete local instance: {}", instanceId, e);
            throw new RuntimeException("Failed to delete local instance: " + e.getMessage(), e);
        }
    }

    @Override
    public InetAddress getInstanceIp(String instanceId) throws InstanceNotFoundException {
        try {
            return InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            logger.error("Failed to get local host address", e);
            throw new InstanceNotFoundException("Unable to determine instance IP");
        }
    }

    @Override
    public List<Region> getAvailableRegions() {
        logger.info("Getting available regions for Local provider");
        List<Region> regions = new ArrayList<>();
        regions.add(new LocalRegion());
        logger.info("Returning {} local regions", regions.size());
        return regions;
    }

    @Override
    public List<Size> getAvailableSizes() {
        logger.info("Getting available sizes for Local provider");
        List<Size> sizes = new ArrayList<>();
        sizes.add(new LocalSize());
        logger.info("Returning {} local sizes", sizes.size());
        return sizes;
    }

    @Override
    public List<Image> getAllImages() {
        logger.info("Getting all images for Local provider");
        List<Image> images = new ArrayList<>();
        images.add(new Image("alpine:latest", "Alpine Linux", "Docker", "alpine:latest", true, List.of("local"),
                new Date(), "local", 0, 0.0, "Alpine Linux", List.of(), "available", null));
        images.add(new Image("ubuntu:latest", "Ubuntu", "Docker", "ubuntu:latest", true, List.of("local"), new Date(),
                "local", 0, 0.0, "Ubuntu", List.of(), "available", null));
        images.add(new Image("fedora:latest", "Fedora", "Docker", "fedora:latest", true, List.of("local"), new Date(),
                "local", 0, 0.0, "Fedora", List.of(), "available", null));
        images.add(new Image("debian:latest", "Debian", "Docker", "debian:latest", true, List.of("local"), new Date(),
                "local", 0, 0.0, "Debian", List.of(), "available", null));
        logger.info("Returning {} local images", images.size());
        return images;
    }

    @Override
    public List<Image> getImagesForRegion(String regionSlug) {
        return getAllImages();
    }

    @Override
    public boolean isConfigured() {
        return true;
    }

    @Override
    public Instance.InstanceStatus getInstanceStatus(String instanceId) {
        logger.info("Getting status for local instance: {}", instanceId);
        try {
            InspectContainerResponse inspectResponse = dockerClient.inspectContainerCmd(instanceId).exec();
            String status = inspectResponse.getState().getStatus();

            if (status == null) {
                logger.warn("Null status received for instance ID: {}", instanceId);
                return Instance.InstanceStatus.ERROR;
            }

            switch (status.toLowerCase()) {
                case "created":
                    return Instance.InstanceStatus.CREATING;
                case "running":
                    return Instance.InstanceStatus.RUNNING;
                case "paused":
                case "exited":
                    return Instance.InstanceStatus.STOPPED;
                case "dead":
                    return Instance.InstanceStatus.DELETED;
                default:
                    logger.warn("Unknown status '{}' for instance ID: {}", status, instanceId);
                    return Instance.InstanceStatus.ERROR;
            }
        } catch (Exception e) {
            logger.error("Error getting instance status for ID: {}", instanceId, e);
            return Instance.InstanceStatus.ERROR;
        }
    }

    private static class LogCollector implements ResultCallback<Frame> {
        private final List<String> logs = new ArrayList<>();
        private final CountDownLatch latch = new CountDownLatch(1);

        @Override
        public void onNext(Frame object) {
            logs.add(new String(object.getPayload()));
        }

        @Override
        public void onStart(Closeable closeable) {
        }

        @Override
        public void onError(Throwable throwable) {
            latch.countDown();
        }

        @Override
        public void onComplete() {
            latch.countDown();
        }

        @Override
        public void close() {
            latch.countDown();
        }

        public String getLogs() {
            return String.join("\n", logs);
        }

        public boolean awaitCompletion(long timeout, TimeUnit timeUnit) throws InterruptedException {
            return latch.await(timeout, timeUnit);
        }
    }

    public String uploadSshKeyIfNeeded(SSHKey sshKey) {
        // For local instances, we don't need to upload the key to a remote service
        // Instead, we'll return a unique identifier for the key
        return sshKey.getId().toString();
    }

    public void deleteSshKeyFromProvider(SSHKey sshKey) {
        // For local instances, we don't need to delete the key from a remote service
        // We can simply log that the key would be removed if this was a remote provider
        logger.info("SSH key removal simulated for local provider: {}", sshKey.getName());
    }

    private String validateAndPullImage(String imageId) throws InterruptedException {
        if (imageId == null || imageId.isEmpty()) {
            imageId = "ubuntu:latest"; // Default image for local instances
            logger.info("Using default image: {}", imageId);
        }

        // Check if the image exists locally
        boolean imageExists = dockerClient.listImagesCmd().withImageNameFilter(imageId).exec().size() > 0;

        if (!imageExists) {
            logger.info("Image {} not found locally. Attempting to pull...", imageId);
            dockerClient.pullImageCmd(imageId)
                    .exec(new PullImageResultCallback())
                    .awaitCompletion(5, TimeUnit.MINUTES);
            logger.info("Image {} pulled successfully", imageId);
        }

        return imageId;
    }

    private String buildContainerCommand(SSHKey sshKey) {
        StringBuilder commandBuilder = new StringBuilder();

        // Detect the base image and install OpenSSH accordingly
        commandBuilder.append("if [ -f /etc/alpine-release ]; then ");
        commandBuilder.append("apk update && apk add openssh && ");
        commandBuilder.append("ssh-keygen -A; "); // Generate host keys for OpenSSH
        commandBuilder.append("elif [ -f /etc/debian_version ]; then ");
        commandBuilder.append("apt-get update && apt-get install -y openssh-server && ");
        commandBuilder.append("ssh-keygen -A && ");
        commandBuilder.append("service ssh start; "); // Start SSH server for Debian
        commandBuilder.append("elif [ -f /etc/fedora-release ]; then ");
        commandBuilder.append("dnf install -y openssh-server && ");
        commandBuilder.append("ssh-keygen -A; "); // Generate host keys for OpenSSH
        commandBuilder.append("else ");
        commandBuilder.append("echo 'Unsupported base image'; exit 1; ");
        commandBuilder.append("fi && ");

        // Create SSH directory and set permissions
        commandBuilder.append("mkdir -p /root/.ssh && chmod 700 /root/.ssh && ");

        if (sshKey != null) {
            String escapedPublicKey = sshKey.getPublicKey().replace("\"", "\\\"");
            commandBuilder.append("echo \"").append(escapedPublicKey).append("\" >> /root/.ssh/authorized_keys && ");
            commandBuilder.append("chmod 600 /root/.ssh/authorized_keys && ");
        }

        // Start the SSH server
        commandBuilder.append("/usr/sbin/sshd && ");
        // Keep the container running
        commandBuilder.append("while true; do sleep 1000; done");

        return commandBuilder.toString();
    }

    private CreateContainerResponse createContainer(String name, String imageId, String cmd) {
        return dockerClient.createContainerCmd(imageId)
                .withName(name)
                .withExposedPorts(ExposedPort.tcp(80), ExposedPort.tcp(22), ExposedPort.udp(4242))
                .withHostConfig(HostConfig.newHostConfig()
                        .withPortBindings(
                                new PortBinding(Ports.Binding.empty(), ExposedPort.tcp(80)),
                                new PortBinding(Ports.Binding.empty(), ExposedPort.tcp(22)),
                                new PortBinding(Ports.Binding.empty(), ExposedPort.udp(4242)))
                        .withCapAdd(Capability.NET_ADMIN))
                .withCmd("/bin/sh", "-c", cmd)
                .exec();
    }

    private void validateContainerRunning(String containerId) {
        InspectContainerResponse inspectResponse = dockerClient.inspectContainerCmd(containerId).exec();
        if (!inspectResponse.getState().getRunning()) {
            LogCollector logCollector = new LogCollector();
            dockerClient.logContainerCmd(containerId)
                    .withStdOut(true)
                    .withStdErr(true)
                    .withTail(50)
                    .exec(logCollector);

            try {
                logCollector.awaitCompletion(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.error("Interrupted while waiting for log collection", e);
            }
            logger.error("Container stopped immediately after starting. Logs: {}", logCollector.getLogs());
            throw new RuntimeException("Container stopped immediately after starting");
        }
    }

    private ContainerInfo getContainerInfo(String containerId) {
        InspectContainerResponse inspectResponse = dockerClient.inspectContainerCmd(containerId).exec();
        Integer hostPort = null;
        String containerIp = null;
        Ports.Binding[] bindings = inspectResponse.getNetworkSettings().getPorts().getBindings()
                .get(ExposedPort.tcp(80));
        if (bindings != null && bindings.length > 0) {
            hostPort = Integer.parseInt(bindings[0].getHostPortSpec());
            logger.info("Container port 80 mapped to host port {}", hostPort);
        } else {
            logger.warn("No port binding found for container {}", containerId);
        }

        containerIp = inspectResponse.getNetworkSettings().getNetworks().values().stream()
                .findFirst()
                .map(ContainerNetwork::getIpAddress)
                .orElse("0.0.0.0");

        logger.info("Container IP address: {}", containerIp);

        return new ContainerInfo(hostPort, containerIp, containerId);
    }

    private Provider getOrCreateProvider() {
        return providerRepository.findById("Local")
                .orElseGet(() -> {
                    logger.info("Creating new Local provider");
                    return providerRepository.save(new Provider("Local"));
                });
    }

    private Instance createInstanceObject(String name, String imageId, String size, ContainerInfo containerInfo,
            Provider provider, SSHKey sshKey) throws UnknownHostException {
        Instance instance = new Instance(provider, "local", InetAddress.getByName(containerInfo.getIp()));
        instance.setName(name);
        instance.setImageId(imageId);
        instance.setSize(size);
        instance.setProviderId(containerInfo.getId());
        instance.setType("local");
        instance.setPort(containerInfo.getPort());
        instance.setStatus(Instance.InstanceStatus.RUNNING);
        instance.setSshKey(sshKey);
        return instance;
    }

    private static class ContainerInfo {
        private final Integer port;
        private final String ip;
        private final String id;

        public ContainerInfo(Integer port, String ip, String id) {
            this.port = port;
            this.ip = ip;
            this.id = id;
        }

        public Integer getPort() {
            return port;
        }

        public String getIp() {
            return ip;
        }

        public String getId() {
            return id;
        }
    }

    public String getSwarmStatus() {
        try {
            return dockerSwarmService.listNodes();
        } catch (Exception e) {
            logger.error("Failed to get Swarm status", e);
            return "Failed to get Swarm status: " + e.getMessage();
        }
    }

}