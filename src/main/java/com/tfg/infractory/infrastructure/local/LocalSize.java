package com.tfg.infractory.infrastructure.local;

import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean; // Added import for OperatingSystemMXBean
import java.lang.management.MemoryMXBean;
import com.tfg.infractory.infrastructure.cloud.model.Size;

public class LocalSize implements Size {
    @Override
    public String getId() {
        return "default";
    }

    @Override
    public String getName() {
        return "Default Local Size";
    }

    @Override
    public String getDescription() {
        return "Default local size for Docker containers";
    }

    @Override
    public int getCpuCount() {
        OperatingSystemMXBean osBean = ManagementFactory.getPlatformMXBean(OperatingSystemMXBean.class);
        return osBean.getAvailableProcessors(); // Get CPU count for the PC
    }

    @Override
    public int getMemoryMB() {
        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();

        long maxHeapMemory = memoryBean.getHeapMemoryUsage().getMax();
        long maxNonHeapMemory = memoryBean.getNonHeapMemoryUsage().getMax();

        // Estimate total memory as 4 times the maximum heap memory
        long estimatedTotalMemory = Math.max(maxHeapMemory * 4, maxHeapMemory + maxNonHeapMemory);

        return (int) (estimatedTotalMemory / (1024 * 1024)); // Convert bytes to MB
    }

    // Implement other methods from the Size interface...
}