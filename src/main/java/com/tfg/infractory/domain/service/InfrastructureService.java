package com.tfg.infractory.domain.service;

import java.util.Set;
import java.util.List;
import org.slf4j.Logger;
import java.util.ArrayList;
import org.slf4j.LoggerFactory;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.annotation.Transactional;

import com.tfg.infractory.domain.model.*;
import com.tfg.infractory.domain.repository.*;
import com.tfg.infractory.web.event.DeployNebulaEvent;
import com.tfg.infractory.infrastructure.ssh.model.SSHKey;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;
import com.tfg.infractory.infrastructure.cloud.model.Details;
import com.tfg.infractory.infrastructure.ssh.service.SSHKeyService;

@Service
public class InfrastructureService {
    private static final Logger logger = LoggerFactory.getLogger(InfrastructureService.class);

    private final ServerRepository serverRepository;
    private final DetailsRepository detailsRepository;
    private final NebulaRepository nebulaRepository;
    private final InstanceRepository instanceRepository;
    private final DomainRepository domainRepository;
    private final InstanceService instanceService;
    private final SSHKeyService sshKeyService;
    private final ApplicationEventPublisher eventPublisher;

    public InfrastructureService(ServerRepository serverRepository,
            DetailsRepository detailsRepository,
            NebulaRepository nebulaRepository,
            InstanceRepository instanceRepository,
            DomainRepository domainRepository,
            InstanceService instanceService,
            SSHKeyService sshKeyService,
            ApplicationEventPublisher eventPublisher) {
        this.serverRepository = serverRepository;
        this.detailsRepository = detailsRepository;
        this.nebulaRepository = nebulaRepository;
        this.instanceRepository = instanceRepository;
        this.domainRepository = domainRepository;
        this.instanceService = instanceService;
        this.sshKeyService = sshKeyService;
        this.eventPublisher = eventPublisher;
    }

    @Transactional
    public void addServers(List<Server> servers) {
        Set<Long> serverIds = servers.stream()
                .map(Server::getId)
                .collect(Collectors.toSet());

        Set<Long> existingServerIds = serverRepository.findAllById(serverIds)
                .stream()
                .map(Server::getId)
                .collect(Collectors.toSet());

        List<Server> newServers = servers.stream()
                .filter(server -> !existingServerIds.contains(server.getId()))
                .collect(Collectors.toList());

        if (!newServers.isEmpty()) {
            for (Server server : newServers) {
                saveServerDependencies(server);
            }
            serverRepository.saveAll(newServers);
        }
    }

    @Transactional
    public Server getServer(Long id) {
        return serverRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Server not found: " + id));
    }

    @Transactional
    public void assignInstanceToServer(Long serverId, Long instanceId) {
        logger.info("Assigning instance {} to server {}", instanceId, serverId);
        Server server = getServer(serverId);
        Instance instance = instanceService.getInstance(instanceId);
        server.setInstance(instance);
        Server savedServer = serverRepository.save(server);
        logger.info("Saved server: {}", savedServer);
    }

    @Transactional
    public Server createServer(String serverType, Long instanceId, String description, Long sshKeyId,
            Nebula nebulaConfig, DockerConfig dockerConfig) {
        Instance instance = instanceService.getInstance(instanceId);
        Details details = new Details(serverType, description);

        SSHKey sshKey = sshKeyService.getSSHKeyById(sshKeyId);
        if (sshKey == null) {
            throw new IllegalArgumentException("Invalid SSH key ID");
        }

        Server server = createServerByType(serverType, instance, nebulaConfig, details, dockerConfig);
        Server savedServer = serverRepository.save(server);
        logger.info("Server saved with ID: {}", savedServer.getId());

        // Get list of lighthouses
        List<Nebula> lighthouses = nebulaRepository.findByLighthouseTrue();

        // Publish nebula deploy event if there are lighthouses deployed
        if (nebulaConfig != null && !lighthouses.isEmpty() &&
                serverRepository.findByVpn(lighthouses.get(0)) != null) {
            eventPublisher.publishEvent(new DeployNebulaEvent(this, savedServer.getId(), nebulaConfig.getId()));
        } else if (nebulaConfig != null && nebulaConfig.getLighthouse()) {
            // This is the first lighthouse, so we can deploy it
            eventPublisher.publishEvent(new DeployNebulaEvent(this, savedServer.getId(), nebulaConfig.getId()));
        } else {
            throw new IllegalStateException(
                    "You need to have a lighthouse deployed before attempting to deploy any other instance");
        }

        return savedServer;
    }

    private Server createServerByType(String serverType, Instance instance, Nebula nebulaConfig, Details details,
            DockerConfig dockerConfig) {
        switch (serverType) {
            case "Phishing":
                return new Phishing(instance, nebulaConfig, details, new ArrayList<>(), new ArrayList<>(),
                        dockerConfig);
            case "Redirector":
                return new Redirector(instance, nebulaConfig, details, new ArrayList<>(), "HTTP", null, null,
                        dockerConfig);
            case "TeamServer":
                return new TeamServer(instance, nebulaConfig, details, new ArrayList<>(), new ArrayList<>(),
                        dockerConfig);
            default:
                throw new IllegalArgumentException("Invalid server type: " + serverType);
        }
    }

    @Transactional
    public Server createServer(Server server) {
        saveServerDependencies(server);
        return serverRepository.save(server);
    }

    @Transactional
    public Server updateServer(Long id, Server serverDetails) {
        Server server = getServer(id);
        server.setInstance(serverDetails.getInstance());
        saveServerDependencies(serverDetails);
        server.setVpn(serverDetails.getVpn());
        server.setDetails(serverDetails.getDetails());
        server.setDomains(serverDetails.getDomains());
        server.setOnline(serverDetails.getOnline());
        server.setActivedomain(serverDetails.getActivedomain());
        return serverRepository.save(server);
    }

    @Transactional
    public void deleteServer(Long id) {
        Server server = getServer(id);

        if (server.getDomains() != null) {
            for (Domain domain : server.getDomains()) {
                domain.setServer(null);
            }
        }
        serverRepository.delete(server);
    }

    public List<Server> getAllServers() {
        return serverRepository.findAll();
    }

    private void saveServerDependencies(Server server) {
        if (server.getInstance() != null) {
            Instance managedInstance = instanceRepository.findById(server.getInstance().getId())
                    .orElse(instanceRepository.save(server.getInstance()));
            server.setInstance(managedInstance);
        }
        if (server.getDetails() != null && server.getDetails().getId() == null) {
            server.setDetails(detailsRepository.save(server.getDetails()));
        }
        if (server.getVpn() != null && server.getVpn().getId() == null) {
            server.setVpn(nebulaRepository.save(server.getVpn()));
        }
        if (server.getDomains() != null) {
            List<Domain> savedDomains = server.getDomains().stream()
                    .filter(domain -> domain != null)
                    .map(domain -> {
                        if (domain.getId() == null) {
                            domain = domainRepository.save(domain);
                        } else {
                            domain = domainRepository.findById(domain.getId()).orElse(domain);
                        }
                        domain.setServer(server);
                        return domain;
                    })
                    .collect(Collectors.toList());
            server.setDomains(savedDomains);
        }
        if (server.getActivedomain() != null && server.getActivedomain().getId() == null) {
            server.setActivedomain(domainRepository.save(server.getActivedomain()));
        }
    }

    @Transactional
    public Nebula saveNebula(Nebula nebula) {
        return nebulaRepository.save(nebula);
    }

    @Transactional
    public Details saveDetails(Details details) {
        return detailsRepository.save(details);
    }

    @Transactional
    public Instance saveInstance(Instance instance) {
        return instanceRepository.save(instance);
    }

    @Transactional
    public Domain saveDomain(Domain domain) {
        return domainRepository.save(domain);
    }

    @Transactional
    public void updateServerInstanceAndDescription(Long serverId, Long instanceId, String description) {
        Server server = getServer(serverId);
        Instance instance = instanceService.getInstance(instanceId);
        server.setInstance(instance);
        server.getDetails().setDescription(description);
        serverRepository.save(server);
    }
}