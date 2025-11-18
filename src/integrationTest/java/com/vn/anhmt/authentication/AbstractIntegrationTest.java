package com.vn.anhmt.authentication;

import com.redis.testcontainers.RedisContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Singleton container pattern for integration tests.
 * Containers are started once and reused across all test classes.
 * They will NOT be stopped after tests complete, allowing for fast reuse in subsequent test runs.
 */
public abstract class AbstractIntegrationTest {

    protected static final PostgreSQLContainer<?> POSTGRES_CONTAINER;
    protected static final RedisContainer REDIS_CONTAINER;

    static {
        POSTGRES_CONTAINER = new PostgreSQLContainer<>("postgres:18-alpine")
                .withLabel("testcontainers.reuse.enable", "true")
                .withReuse(true);
        POSTGRES_CONTAINER.start();

        REDIS_CONTAINER = new RedisContainer(DockerImageName.parse("redis:7.2-alpine"))
                .withLabel("testcontainers.reuse.enable", "true")
                .withReuse(true);
        REDIS_CONTAINER.start();

        // Ensure containers are not stopped when JVM exits
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            // Do nothing - keep containers running for reuse
        }));
    }
}
