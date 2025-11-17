package com.vn.anhmt.authentication;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AuthServerApplicationIntegrationTest extends BaseIntegrationTest {

    @Test
    public void contextLoads() {
        Assertions.assertNotNull(postgresDB);
        Assertions.assertNotNull(redisContainer);
        Assertions.assertTrue(postgresDB.isRunning());
        Assertions.assertTrue(redisContainer.isRunning());
    }

    @Test
    public void containersAreReused() {
        Assertions.assertTrue(postgresDB.isRunning());
        Assertions.assertTrue(redisContainer.isRunning());
        Assertions.assertNotNull(postgresDB.getContainerId());
        Assertions.assertNotNull(redisContainer.getContainerId());
    }
}
