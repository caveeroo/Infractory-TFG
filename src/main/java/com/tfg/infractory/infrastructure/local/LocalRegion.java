package com.tfg.infractory.infrastructure.local;

import com.tfg.infractory.infrastructure.cloud.model.Region;

public class LocalRegion implements Region {
    @Override
    public String getId() {
        return "local";
    }

    @Override
    public String getName() {
        return "Local";
    }

    @Override
    public boolean isAvailable() {
        return true;
    }
}