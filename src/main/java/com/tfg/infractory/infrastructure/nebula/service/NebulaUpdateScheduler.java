package com.tfg.infractory.infrastructure.nebula.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.beans.factory.annotation.Autowired;

@Component
public class NebulaUpdateScheduler {

    private static final Logger logger = LoggerFactory.getLogger(NebulaUpdateScheduler.class);

    @Autowired
    private LighthouseService lighthouseService;

    @Scheduled(fixedRate = 3600000) // Run every hour
    public void updateLighthouseIps() {
        logger.info("Starting scheduled update of lighthouse IPs");
        lighthouseService.updateLighthouseIps();
        logger.info("Completed scheduled update of lighthouse IPs");
    }
}