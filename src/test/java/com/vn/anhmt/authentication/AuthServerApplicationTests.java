package com.vn.anhmt.authentication;

import com.redis.testcontainers.RedisContainer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class AuthServerApplicationTests {

    @Container
    @ServiceConnection
    public static final PostgreSQLContainer<?> postgresDB = new PostgreSQLContainer<>("postgres:18-alpine");

    @Container
    @ServiceConnection
    private static final RedisContainer redisContainer = new RedisContainer(DockerImageName.parse("redis:7.2-alpine"));

    @Test
    void contextLoads() {
        Assertions.assertNotNull(postgresDB);
        Assertions.assertNotNull(redisContainer);
    }

    @BeforeAll
    static void destroy() {
        if (postgresDB.isRunning()) {
            postgresDB.stop();
        }

        if (redisContainer.isRunning()) {
            redisContainer.stop();
        }
    }
}
