package com.vn.anhmt.authentication;

import com.redis.testcontainers.RedisContainer;
import com.vn.anhmt.authentication.configuration.RestTestConfiguration;
import com.vn.anhmt.authentication.repository.OAuth2AuthorizationJpaRepository;
import com.vn.anhmt.authentication.repository.OAuth2RegisteredClientJpaRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.shaded.com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Import(RestTestConfiguration.class)
public abstract class BaseIntegrationTest extends AbstractIntegrationTest {

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES_CONTAINER::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES_CONTAINER::getUsername);
        registry.add("spring.datasource.password", POSTGRES_CONTAINER::getPassword);
        registry.add("spring.data.redis.host", REDIS_CONTAINER::getHost);
        registry.add("spring.data.redis.port", () -> REDIS_CONTAINER.getMappedPort(6379));
    }

    // Aliases for backward compatibility
    protected static final PostgreSQLContainer<?> postgresDB = POSTGRES_CONTAINER;
    protected static final RedisContainer redisContainer = REDIS_CONTAINER;

    @LocalServerPort
    protected int port;

    @Autowired
    protected RestTemplate restTemplate;

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected OAuth2RegisteredClientJpaRepository oauth2RegisteredClientJpaRepository;

    @Autowired
    protected OAuth2AuthorizationJpaRepository oauth2AuthorizationJpaRepository;

    protected ObjectMapper objectMapper = new ObjectMapper();

    protected String getBaseUrl() {
        return "http://localhost:" + port + "/";
    }
}
