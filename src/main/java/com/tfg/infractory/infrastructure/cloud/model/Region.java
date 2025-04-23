package com.tfg.infractory.infrastructure.cloud.model;

public interface Region {
    String getId();

    String getName();

    boolean isAvailable();
    // Add any other common properties
}