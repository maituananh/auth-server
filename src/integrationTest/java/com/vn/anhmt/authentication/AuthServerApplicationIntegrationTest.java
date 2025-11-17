package com.vn.anhmt.authentication;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class AuthServerApplicationIntegrationTest extends BaseIntegrationTest {

    @Test
    void contextLoads() {
        Assertions.assertNotNull(postgresDB);
        Assertions.assertNotNull(redisContainer);
        Assertions.assertTrue(postgresDB.isRunning());
        Assertions.assertTrue(redisContainer.isRunning());
    }

    @Test
    void containersAreReused() {
        Assertions.assertTrue(postgresDB.isRunning());
        Assertions.assertTrue(redisContainer.isRunning());
        Assertions.assertNotNull(postgresDB.getContainerId());
        Assertions.assertNotNull(redisContainer.getContainerId());
    }
}
