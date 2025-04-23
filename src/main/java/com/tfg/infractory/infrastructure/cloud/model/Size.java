package com.tfg.infractory.infrastructure.cloud.model;

public interface Size {
    String getId();

    String getName(); // Add this method

    int getCpuCount();

    int getMemoryMB();

    String getDescription();

    // Return the CPU architecture (x86_64 or arm64)
    default String getArchitecture() {
        return "x86_64"; // Default to x86_64 for backward compatibility
    }
    // Add any other common properties
}