package com.tfg.infractory.infrastructure.nebula.service;

import java.util.Set;
import java.util.List;
import org.slf4j.Logger;
import java.util.ArrayList;
import java.net.InetAddress;
import org.slf4j.LoggerFactory;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.net.UnknownHostException;
import org.springframework.stereotype.Service;
import org.springframework.cache.annotation.Caching;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import com.tfg.infractory.web.dto.NebulaConfigurationDTO;
import com.tfg.infractory.domain.model.Instance;
import com.tfg.infractory.domain.model.Server;
import com.tfg.infractory.infrastructure.cloud.model.Nebula;
import com.tfg.infractory.infrastructure.secrets.service.SecretsService;
import com.tfg.infractory.domain.repository.NebulaRepository;
import com.tfg.infractory.domain.repository.ServerRepository;

@Service
public class NebulaService {

    private static final Logger logger = LoggerFactory.getLogger(NebulaService.class);
    private static final String IP_PATTERN = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

    private final NebulaRepository nebulaRepository;

    @Autowired
    private SecretsService secretsService;

    @Autowired
    private LighthouseService lighthouseService;

    @Autowired
    private ServerRepository serverRepository;

    @Autowired
    public NebulaService(NebulaRepository nebulaRepository) {
        this.nebulaRepository = nebulaRepository;
    }

    @Transactional
    public Nebula createNebulaConfig(NebulaConfigurationDTO nebulaConfig) {
        try {
            Nebula nebula = new Nebula();
            nebula.setLighthouse(nebulaConfig.getLighthouse());
            nebula.setRoles(nebulaConfig.getRoles());
            nebula.setAllowedCIDRs(nebulaConfig.getAllowedCIDRs());
            nebula.setAllowedRoles(nebulaConfig.getAllowedRoles());
            nebula.setPlacementConstraints(nebulaConfig.getPlacementConstraints());

            if (nebula.getLighthouse()) {
                if (nebulaConfig.getIp() == null || nebulaConfig.getSubnet() == null) {
                    throw new IllegalArgumentException("IP and subnet must be provided for a lighthouse configuration");
                }
                nebula.setIp(nebulaConfig.getIp());
                nebula.setSubnet(nebulaConfig.getSubnet());
            } else {
                if (nebulaConfig.getLighthouseId() == null) {
                    throw new IllegalArgumentException(
                            "Lighthouse ID must be provided for a non-lighthouse configuration");
                }
                Nebula lighthouse = getNebulaConfigById(nebulaConfig.getLighthouseId());
                nebula.setSubnet(lighthouse.getSubnet());
                nebula.setIp(findNextAvailableIp(lighthouse));
            }

            setLighthouseIps(nebula, nebulaConfig.getLighthouseIps());

            Nebula savedNebula = nebulaRepository.save(nebula);
            logger.info("Saved Nebula configuration: {}", savedNebula);

            saveStaticHosts(savedNebula);

            return savedNebula;
        } catch (Exception e) {
            logger.error("Failed to create Nebula configuration. Error: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create Nebula configuration", e);
        }
    }

    public List<Nebula> getAllLighthouseConfigs() {
        return nebulaRepository.findByLighthouseTrue();
    }

    private String findNextAvailableIp(Nebula lighthouse) {
        String baseIp = lighthouse.getIp();
        int subnet = lighthouse.getSubnet();

        // Extract the subnet prefix (first three octets)
        String subnetPrefix = baseIp.substring(0, baseIp.lastIndexOf('.'));

        List<String> usedIps = nebulaRepository.findIpsInSubnet(subnetPrefix);

        if (usedIps == null) {
            usedIps = new ArrayList<>();
        }

        try {
            InetAddress inetAddress = InetAddress.getByName(baseIp);
            byte[] bytes = inetAddress.getAddress();
            int ipValue = ((bytes[0] & 0xFF) << 24) |
                    ((bytes[1] & 0xFF) << 16) |
                    ((bytes[2] & 0xFF) << 8) |
                    ((bytes[3] & 0xFF));

            int maskBits = 32 - subnet;
            int mask = 0xFFFFFFFF << maskBits;
            int network = ipValue & mask;
            int broadcast = network | ~mask;

            for (int i = network + 1; i < broadcast; i++) {
                String candidateIp = String.format("%d.%d.%d.%d",
                        (i >> 24 & 0xFF),
                        (i >> 16 & 0xFF),
                        (i >> 8 & 0xFF),
                        (i & 0xFF));

                if (!usedIps.contains(candidateIp)) {
                    return candidateIp;
                }
            }

            throw new RuntimeException("No available IP addresses in the subnet");
        } catch (UnknownHostException e) {
            throw new RuntimeException("Invalid base IP address", e);
        }
    }

    private void setLighthouseIps(Nebula nebula, Set<String> providedLighthouseIps) {
        if (nebula.getLighthouse()) {
            nebula.setLighthouseIps(null);
        } else {
            if (providedLighthouseIps == null || providedLighthouseIps.isEmpty()) {
                List<Nebula> lighthouses = nebulaRepository.findByLighthouseTrue();
                if (lighthouses.isEmpty()) {
                    throw new RuntimeException("No lighthouse found");
                }
                Set<String> lighthouseIps = lighthouses.stream()
                        .map(Nebula::getIp)
                        .collect(Collectors.toSet());
                nebula.setLighthouseIps(lighthouseIps);
            } else {
                nebula.setLighthouseIps(providedLighthouseIps);
            }
            validateLighthouseIps(nebula.getLighthouseIps());
        }
    }

    private void saveStaticHosts(Nebula savedNebula) {
        List<Server> servers = serverRepository.findAll();
        String staticHosts = generateStaticHosts(savedNebula, servers);

        secretsService.addSecret("nebula_static_hosts_" + savedNebula.getId(), "NEBULA_STATIC_HOSTS", staticHosts);
        logger.info("Saved static hosts for Nebula configuration ID: {}", savedNebula.getId());
    }

    private void validateLighthouseIps(Set<String> ips) {
        if (ips != null && !ips.isEmpty()) {
            boolean allValid = ips.stream().allMatch(ip -> Pattern.matches(IP_PATTERN, ip));
            if (!allValid) {
                throw new IllegalArgumentException("One or more lighthouse IPs are invalid");
            }
        }
    }

    private String generateStaticHosts(Nebula nebula, List<Server> servers) {
        return servers.stream()
                .filter(server -> server.getInstance() != null && server.getInstance().getIp() != null
                        && server.getVpn() != null)
                .map(server -> {
                    Instance instance = server.getInstance();
                    Nebula serverNebula = server.getVpn();
                    return String.format("%s: [\"%s\", \"%s\"]",
                            instance.getName(),
                            instance.getIp().getHostAddress(),
                            serverNebula.getIp());
                })
                .collect(Collectors.joining("\n"));
    }

    @Caching(evict = {
            @CacheEvict(value = "nebulaConfigs", key = "#id"),
            @CacheEvict(value = "allNebulaConfigs", allEntries = true)
    })
    @Transactional
    public Nebula updateNebulaConfig(Long id, Nebula updatedNebula) {
        Nebula nebula = nebulaRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Nebula config not found"));
        nebula.setLighthouse(updatedNebula.getLighthouse());
        nebula.setIp(updatedNebula.getIp());
        nebula.setSubnet(updatedNebula.getSubnet());
        nebula.setRoles(updatedNebula.getRoles());
        nebula.setAllowedCIDRs(updatedNebula.getAllowedCIDRs());
        nebula.setAllowedRoles(updatedNebula.getAllowedRoles());

        if (updatedNebula.getLighthouse()) {
            nebula.setLighthouseIps(null);
        } else {
            validateLighthouseIps(updatedNebula.getLighthouseIps());
            if (updatedNebula.getLighthouseIps() == null || updatedNebula.getLighthouseIps().isEmpty()) {
                Set<String> availableLighthouseIps = lighthouseService.getAvailableLighthouseIps();
                nebula.setLighthouseIps(availableLighthouseIps);
            } else {
                nebula.setLighthouseIps(updatedNebula.getLighthouseIps());
            }
        }

        return nebulaRepository.save(nebula);
    }

    @Caching(evict = {
            @CacheEvict(value = "nebulaConfigs", key = "#id"),
            @CacheEvict(value = "allNebulaConfigs", allEntries = true)
    })
    @Transactional
    public void deleteNebulaConfig(Long id) {
        Nebula nebula = nebulaRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Nebula config not found"));

        // Find the server associated with this Nebula config
        Server server = serverRepository.findByVpn(nebula);
        if (server != null) {
            server.setVpn(null);
            serverRepository.save(server);
        }

        nebulaRepository.deleteById(id);
    }

    @Cacheable(value = "allNebulaConfigs")
    public List<Nebula> getAllNebulaConfigs() {
        List<Nebula> configs = nebulaRepository.findAllWithCollections();
        // logger.info("Retrieved {} Nebula configurations", configs.size());
        return configs;
    }

    @CacheEvict(value = "allNebulaConfigs", allEntries = true)
    public void refreshNebulaConfigsCache() {
        // logger.info("Refreshing Nebula configurations cache");
    }

    public List<Nebula> refreshAndGetAllNebulaConfigs() {
        refreshNebulaConfigsCache();
        return getAllNebulaConfigs();
    }

    // @Cacheable(value = "nebulaConfigs", key = "#id")
    public Nebula getNebulaConfigById(Long id) {
        return nebulaRepository.findByIdWithAllCollections(id)
                .orElseThrow(() -> new RuntimeException("Nebula config not found"));
    }
}