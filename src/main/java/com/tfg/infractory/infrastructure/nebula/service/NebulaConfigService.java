package com.tfg.infractory.infrastructure.nebula.service;

import java.util.Set;
import java.util.List;
import org.slf4j.Logger;
import java.util.HashSet;
import java.util.Optional;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import com.tfg.infractory.infrastructure.cloud.model.Nebula;
import com.tfg.infractory.domain.repository.NebulaRepository;

@Service
public class NebulaConfigService {

    private static final Logger logger = LoggerFactory.getLogger(NebulaConfigService.class);

    @Autowired
    private NebulaRepository nebulaRepository;

    @Autowired
    private LighthouseService lighthouseService;

    public Nebula createNebulaConfig(Nebula nebula) {
        logger.info("Creating new Nebula configuration: {}", nebula);
        if (nebula.getLighthouse()) {
            nebula.setLighthouseIps(new HashSet<>(Set.of(nebula.getIp())));
        } else {
            Set<String> availableLighthouseIps = lighthouseService.getAvailableLighthouseIps();
            nebula.setLighthouseIps(availableLighthouseIps);
        }
        Nebula savedNebula = nebulaRepository.save(nebula);
        logger.info("Saved Nebula configuration: {}", savedNebula);
        return savedNebula;
    }

    public Nebula updateNebulaConfig(Long id, Boolean lighthouse, String ip, Integer subnet, Set<String> roles,
            Set<String> allowedCIDRs, Set<String> allowedRoles) {
        Nebula nebula = nebulaRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Nebula config not found"));
        nebula.setLighthouse(lighthouse);
        nebula.setIp(ip);
        nebula.setSubnet(subnet);
        nebula.setRoles(roles);
        nebula.setAllowedCIDRs(allowedCIDRs);
        nebula.setAllowedRoles(allowedRoles);

        if (lighthouse) {
            nebula.setLighthouseIps(new HashSet<>(Set.of(ip)));
        } else {
            Set<String> availableLighthouseIps = lighthouseService.getAvailableLighthouseIps();
            nebula.setLighthouseIps(availableLighthouseIps);
        }

        return nebulaRepository.save(nebula);
    }

    public void deleteNebulaConfig(Long id) {
        nebulaRepository.deleteById(id);
    }

    public List<Nebula> getAllNebulaConfigs() {
        List<Nebula> configs = nebulaRepository.findAll();
        // logger.info("Retrieved {} Nebula configurations", configs.size());
        return configs;
    }

    public Nebula getNebulaConfigById(Long id) {
        Optional<Nebula> nebulaConfig = nebulaRepository.findById(id);
        return nebulaConfig.orElseThrow(() -> new RuntimeException("Nebula config not found"));
    }
}