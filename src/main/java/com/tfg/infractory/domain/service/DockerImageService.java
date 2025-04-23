package com.tfg.infractory.domain.service;

import java.util.List;
import org.springframework.util.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import com.tfg.infractory.domain.model.DockerImage;
import com.tfg.infractory.domain.repository.DockerImageRepository;

@Service
public class DockerImageService {

    @Autowired
    private DockerImageRepository dockerImageRepository;

    public DockerImage createDockerImage(DockerImage dockerImage) {
        validateDockerImage(dockerImage);
        return dockerImageRepository.save(dockerImage);
    }

    private void validateDockerImage(DockerImage dockerImage) {
        if (!StringUtils.hasText(dockerImage.getName())) {
            throw new IllegalArgumentException("Docker image name cannot be empty");
        }
        if (!StringUtils.hasText(dockerImage.getTag())) {
            throw new IllegalArgumentException("Docker image tag cannot be empty");
        }
        if (!StringUtils.hasText(dockerImage.getRepository())) {
            throw new IllegalArgumentException("Docker image repository cannot be empty");
        }
    }

    public List<DockerImage> getAllDockerImages() {
        return dockerImageRepository.findAll();
    }

    public DockerImage getDockerImageById(Long id) {
        return dockerImageRepository.findById(id).orElse(null);
    }

    public void updateDockerImage(Long id, DockerImage updatedImage) {
        DockerImage existingImage = getDockerImageById(id);
        if (existingImage != null) {
            existingImage.setName(updatedImage.getName());
            existingImage.setTag(updatedImage.getTag());
            existingImage.setRepository(updatedImage.getRepository());
            dockerImageRepository.save(existingImage);
        }
    }

    public void deleteDockerImage(Long id) {
        dockerImageRepository.deleteById(id);
    }
}