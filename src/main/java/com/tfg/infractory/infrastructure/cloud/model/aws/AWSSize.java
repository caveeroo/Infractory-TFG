package com.tfg.infractory.infrastructure.cloud.model.aws;

import com.tfg.infractory.infrastructure.cloud.model.Size;

public class AWSSize implements Size {
    private String id;
    private String name;
    private int cpuCount;
    private int memoryMB;
    private String architecture;

    public AWSSize(String id, String name, int cpuCount, int memoryMB) {
        this.id = id;
        this.name = name;
        this.cpuCount = cpuCount;
        this.memoryMB = memoryMB;
        this.architecture = "x86_64";
    }

    public AWSSize(String id, String name, int cpuCount, int memoryMB, String architecture) {
        this.id = id;
        this.name = name;
        this.cpuCount = cpuCount;
        this.memoryMB = memoryMB;
        this.architecture = architecture;
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
    public int getCpuCount() {
        return cpuCount;
    }

    @Override
    public int getMemoryMB() {
        return memoryMB;
    }

    public String getArchitecture() {
        return architecture;
    }

    @Override
    public String getDescription() {
        return String.format("%s - %d vCPUs, %d MB RAM (%s)", name, cpuCount, memoryMB, architecture);
    }
}
