package com.vn.anhmt.authentication;

import com.redis.testcontainers.RedisContainer;
import com.vn.anhmt.authentication.configuration.RestTestConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.shaded.com.fasterxml.jackson.databind.ObjectMapper;
import org.testcontainers.utility.DockerImageName;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
@AutoConfigureMockMvc
@Import(RestTestConfiguration.class)
public abstract class BaseIntegrationTest {

    @Container
    @ServiceConnection
    protected static final PostgreSQLContainer<?> postgresDB =
            new PostgreSQLContainer<>("postgres:18-alpine").withReuse(true);

    @Container
    @ServiceConnection
    protected static final RedisContainer redisContainer =
            new RedisContainer(DockerImageName.parse("redis:7.2-alpine")).withReuse(true);

    @LocalServerPort
    protected int port;

    @Autowired
    protected RestTemplate restTemplate;

    protected ObjectMapper objectMapper = new ObjectMapper();

    protected String getBaseUrl() {
        return "http://localhost:" + port + "/";
    }
}
