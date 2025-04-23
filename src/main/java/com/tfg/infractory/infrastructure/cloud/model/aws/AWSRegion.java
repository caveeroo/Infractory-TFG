package com.tfg.infractory.infrastructure.cloud.model.aws;

import com.tfg.infractory.infrastructure.cloud.model.Region;

public class AWSRegion implements Region {
    private String id;
    private String name;

    public AWSRegion(String id, String name) {
        this.id = id;
        this.name = name;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean isAvailable() {
        return true; // Or implement your logic here
    }

}
