package com.tfg.infractory.infrastructure.cloud.service;

import java.util.List;
import java.net.InetAddress;

import com.tfg.infractory.domain.model.Instance;
import com.tfg.infractory.infrastructure.cloud.model.Size;
import com.tfg.infractory.infrastructure.ssh.model.SSHKey;
import com.tfg.infractory.infrastructure.cloud.model.Image;
import com.tfg.infractory.infrastructure.cloud.model.Region;
import com.tfg.infractory.domain.exception.InstanceNotFoundException;

public interface CloudProviderService {
    Instance createInstance(String name, String imageId, String size, String region, SSHKey sshKey);

    void deleteInstance(String instanceId);

    InetAddress getInstanceIp(String instanceId) throws InstanceNotFoundException;

    List<Region> getAvailableRegions();

    List<Size> getAvailableSizes();

    /**
     * Returns a list of instance sizes compatible with the given image ID
     * 
     * @param imageId The image ID to check compatibility for
     * @return List of compatible instance sizes
     */
    default List<Size> getCompatibleSizesForImage(String imageId) {
        // By default, return all available sizes
        return getAvailableSizes();
    }

    List<Image> getAllImages();

    List<Image> getImagesForRegion(String regionSlug);

    boolean isConfigured();

    Instance.InstanceStatus getInstanceStatus(String instanceId) throws InstanceNotFoundException;
}