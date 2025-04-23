package com.tfg.infractory;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.retry.annotation.EnableRetry;

import com.tfg.infractory.domain.service.InitializationService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@EnableRetry
@EnableCaching
@SpringBootApplication
@EnableJpaRepositories(basePackages = {
        "com.tfg.infractory.domain.repository",
        "com.tfg.infractory.infrastructure.cloud.repository",
        "com.tfg.infractory.infrastructure.docker.repository",
        "com.tfg.infractory.infrastructure.nebula.repository",
        "com.tfg.infractory.infrastructure.secrets.repository",
        "com.tfg.infractory.infrastructure.ssh.repository",
})
@EntityScan(basePackages = {
        "com.tfg.infractory.domain.model",
        "com.tfg.infractory.infrastructure.cloud.model",
        "com.tfg.infractory.infrastructure.local.model",
        "com.tfg.infractory.infrastructure.docker.model",
        "com.tfg.infractory.infrastructure.nebula.model",
        "com.tfg.infractory.infrastructure.secrets.model",
        "com.tfg.infractory.infrastructure.ssh.model"
})
@ComponentScan(basePackages = {
        "com.tfg.infractory",
        "com.tfg.infractory.infrastructure.local"
})
@EnableScheduling
public class InfractoryApplication {

    private static final Logger logger = LoggerFactory.getLogger(InfractoryApplication.class);

    public static void main(String[] args) {
        ConfigurableApplicationContext context = SpringApplication.run(InfractoryApplication.class, args);

        // Log all beans to verify LocalProviderService is present
        String[] beanNames = context.getBeanDefinitionNames();
        logger.info("Beans loaded:");
        for (String beanName : beanNames) {
            logger.info(beanName);
        }
    }

    @Bean
    CommandLineRunner initData(InitializationService initializationService) {
        return args -> {
            logger.info("Starting data initialization...");
            try {
                initializationService.initializeData();
                logger.info("Data initialization completed successfully.");
            } catch (Exception e) {
                logger.error("Error during data initialization", e);
            }
        };
    }

    /**
     * Creates an ExecutorService bean for asynchronous task execution.
     * This is used by various services including DockerSwarmService for
     * running background tasks like Docker Swarm initialization.
     * 
     * @return An ExecutorService instance
     */
    @Bean
    public ExecutorService executorService() {
        return Executors.newCachedThreadPool();
    }
}
