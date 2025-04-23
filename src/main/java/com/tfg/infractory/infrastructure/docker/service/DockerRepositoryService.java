package com.tfg.infractory.infrastructure.docker.service;

import org.springframework.stereotype.Service;

@Service
public class DockerRepositoryService {

    private String customRepositoryUrl;

    public void setCustomRepository(String url) {
        this.customRepositoryUrl = url;
    }

    public String getCustomRepository() {
        return customRepositoryUrl;
    }

    public String getImageUrl(String imageName) {
        if (customRepositoryUrl != null && !customRepositoryUrl.isEmpty()) {
            return customRepositoryUrl + "/" + imageName;
        }
        return imageName;
    }
}