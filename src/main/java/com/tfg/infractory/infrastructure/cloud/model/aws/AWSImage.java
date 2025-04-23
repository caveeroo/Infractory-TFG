package com.tfg.infractory.infrastructure.cloud.model.aws;

import java.util.Date;
import java.util.List;
import java.util.Collections;

import com.tfg.infractory.infrastructure.cloud.model.Image;

public class AWSImage extends Image {
    private String architecture = "x86_64"; // Default to x86_64

    public AWSImage(String id, String name, String description, Date createdAt, List<String> regions) {
        super(
                id, // id - Now directly use the AMI string ID
                name, // name
                extractDistribution(name), // distribution
                id, // slug - Using the AMI ID as slug
                true, // isPublic
                regions, // regions
                createdAt, // createdAt
                "ami", // type
                8, // minDiskSize (default to 8GB)
                0.0, // sizeGigabytes (not available from AWS)
                description, // description
                Collections.emptyList(), // tags
                "available", // status
                null // errorMessage
        );

        // Extract architecture from description if available
        if (description != null) {
            if (description.toLowerCase().contains("arm64") ||
                    description.toLowerCase().contains("arm") ||
                    description.toLowerCase().contains("aarch64")) {
                this.architecture = "arm64";
            }
        }
    }

    public AWSImage(String id, String name, String description, Date createdAt, List<String> regions,
            String architecture) {
        this(id, name, description, createdAt, regions);
        this.architecture = architecture;
    }

    public String getArchitecture() {
        return architecture;
    }

    private static String extractDistribution(String name) {
        if (name == null) {
            return "Unknown";
        }

        String lowerName = name.toLowerCase();
        if (lowerName.contains("ubuntu")) {
            return "Ubuntu";
        } else if (lowerName.contains("amzn") || lowerName.contains("amazon")) {
            return "Amazon Linux";
        } else if (lowerName.contains("debian")) {
            return "Debian";
        } else if (lowerName.contains("centos")) {
            return "CentOS";
        } else if (lowerName.contains("fedora")) {
            return "Fedora";
        } else if (lowerName.contains("rhel") || lowerName.contains("red hat")) {
            return "Red Hat Enterprise Linux";
        } else if (lowerName.contains("suse")) {
            return "SUSE Linux";
        }

        return "Unknown";
    }
}