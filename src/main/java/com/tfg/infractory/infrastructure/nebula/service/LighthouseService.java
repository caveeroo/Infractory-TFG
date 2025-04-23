package com.tfg.infractory.infrastructure.nebula.service;

import java.util.Set;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import com.tfg.infractory.infrastructure.cloud.model.Nebula;
import com.tfg.infractory.domain.repository.NebulaRepository;

@Service
public class LighthouseService {

    private static final Logger logger = LoggerFactory.getLogger(LighthouseService.class);

    @Autowired
    private NebulaRepository nebulaRepository;

    public Set<String> getAvailableLighthouseIps() {
        List<Nebula> lighthouses = nebulaRepository.findByLighthouseTrue();
        Set<String> lighthouseIps = lighthouses.stream()
                .map(Nebula::getIp)
                .collect(Collectors.toSet());
        logger.info("Available lighthouse IPs: {}", lighthouseIps);
        return lighthouseIps;
    }

    public void updateLighthouseIps() {
        Set<String> lighthouseIps = getAvailableLighthouseIps();
        List<Nebula> nonLighthouses = nebulaRepository.findByLighthouseFalse();

        for (Nebula nebula : nonLighthouses) {
            nebula.setLighthouseIps(lighthouseIps);
            nebulaRepository.save(nebula);
        }

        logger.info("Updated lighthouse IPs for {} non-lighthouse Nebula configs", nonLighthouses.size());
    }
}