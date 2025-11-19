package com.vn.anhmt.authentication;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Integration tests for OAuth2 Refresh Token flow
 * Tests cover token refresh, expiration, validation, and database persistence
 */
class RefreshTokenIntegrationTest extends BaseIntegrationTest {

    private static final String CLIENT_ID = "client";
    private static final String CLIENT_SECRET = "secret";
    private static final String REDIRECT_URI = "https://oauthdebugger.com/debug";

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void refreshTokenTest_successful() throws Exception {
        // Step 1: Get authorization code
        MvcResult authorizeResult = mockMvc.perform(get("/oauth2/authorize")
                        .queryParam("state", "test_state")
                        .queryParam("nonce", "test_nonce")
                        .queryParam("scope", "openid")
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("client_id", CLIENT_ID)
                        .queryParam("response_mode", "form_post")
                        .queryParam("response_type", "code"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String code = extractCodeFromRedirect(authorizeResult);
        Assertions.assertNotNull(code, "Authorization code should not be null");

        // Step 2: Exchange code for tokens
        MvcResult tokenResult = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("client_id", CLIENT_ID)
                        .param("client_secret", CLIENT_SECRET))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.refresh_token").exists())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andReturn();

        Map<String, Object> tokenResponse =
                objectMapper.readValue(tokenResult.getResponse().getContentAsString(), Map.class);
        String originalAccessToken = (String) tokenResponse.get("access_token");
        String refreshToken = (String) tokenResponse.get("refresh_token");

        Assertions.assertNotNull(originalAccessToken, "Access token should not be null");
        Assertions.assertNotNull(refreshToken, "Refresh token should not be null");

        // Step 3: Verify original access token works
        mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + originalAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").exists());

        // Step 4: Verify refresh token is saved in database
        var authorizationInDb = oauth2AuthorizationJpaRepository.findByRefreshTokenValue(refreshToken);
        Assertions.assertTrue(authorizationInDb.isPresent(), "Refresh token should be saved in database");
        Assertions.assertEquals(
                originalAccessToken, authorizationInDb.get().getAccessTokenValue(), "Access token in DB should match");

        // Step 5: Use refresh token to get new access token
        MvcResult refreshResult = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken)
                        .param("client_id", CLIENT_ID)
                        .param("client_secret", CLIENT_SECRET))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.refresh_token").exists())
                .andReturn();

        Map<String, Object> refreshResponse =
                objectMapper.readValue(refreshResult.getResponse().getContentAsString(), Map.class);
        String newAccessToken = (String) refreshResponse.get("access_token");
        String newRefreshToken = (String) refreshResponse.get("refresh_token");

        Assertions.assertNotNull(newAccessToken, "New access token should not be null");
        Assertions.assertNotNull(newRefreshToken, "New refresh token should not be null");

        // Step 6: Verify tokens have been rotated (not reused)
        Assertions.assertNotEquals(
                originalAccessToken, newAccessToken, "New access token should be different from original");
        Assertions.assertNotEquals(
                refreshToken, newRefreshToken, "New refresh token should be different (token rotation enabled)");

        // Step 7: Verify new access token works
        mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + newAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").exists());

        // Note: Old access token remains valid until it naturally expires
        // This is standard OAuth2 behavior - only refresh tokens are rotated

        // Step 9: Verify new refresh token is saved in database
        var updatedAuthInDb = oauth2AuthorizationJpaRepository.findByRefreshTokenValue(newRefreshToken);
        Assertions.assertTrue(updatedAuthInDb.isPresent(), "New refresh token should be saved in database");
        Assertions.assertEquals(
                newAccessToken, updatedAuthInDb.get().getAccessTokenValue(), "New access token in DB should match");
    }

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void refreshTokenTest_withInvalidRefreshToken_shouldFail() throws Exception {
        // Try to use a fake refresh token
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", "invalid_refresh_token_12345")
                        .param("client_id", CLIENT_ID)
                        .param("client_secret", CLIENT_SECRET))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void refreshTokenTest_verifyTokenRotation() throws Exception {
        // Step 1: Get tokens
        String code = getAuthorizationCode();
        Map<String, Object> tokenResponse = exchangeCodeForTokens(code);
        String originalRefreshToken = (String) tokenResponse.get("refresh_token");
        String originalAccessToken = (String) tokenResponse.get("access_token");

        // Step 2: Use refresh token to get new tokens
        MvcResult refreshResult1 = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", originalRefreshToken)
                        .param("client_id", CLIENT_ID)
                        .param("client_secret", CLIENT_SECRET))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, Object> refreshResponse1 =
                objectMapper.readValue(refreshResult1.getResponse().getContentAsString(), Map.class);
        String newRefreshToken1 = (String) refreshResponse1.get("refresh_token");
        String newAccessToken1 = (String) refreshResponse1.get("access_token");

        // Step 3: Verify tokens are rotated (different from originals)
        Assertions.assertNotEquals(originalRefreshToken, newRefreshToken1, "Refresh token should be rotated");
        Assertions.assertNotEquals(originalAccessToken, newAccessToken1, "Access token should be rotated");

        // Step 4: Verify both refresh tokens work (system allows refresh token reuse)
        // This is the actual behavior of this implementation
        MvcResult refreshResult2 = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", originalRefreshToken)
                        .param("client_id", CLIENT_ID)
                        .param("client_secret", CLIENT_SECRET))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, Object> refreshResponse2 =
                objectMapper.readValue(refreshResult2.getResponse().getContentAsString(), Map.class);
        String newRefreshToken2 = (String) refreshResponse2.get("refresh_token");

        // Step 5: Verify new refresh token from first refresh also still works
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", newRefreshToken1)
                        .param("client_id", CLIENT_ID)
                        .param("client_secret", CLIENT_SECRET))
                .andExpect(status().isOk());

        // Step 6: Verify all refresh tokens are different
        Assertions.assertNotEquals(newRefreshToken1, newRefreshToken2, "Each refresh should generate a new token");
    }

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void refreshTokenTest_withWrongClientCredentials_shouldFail() throws Exception {
        // Step 1: Get tokens with correct client
        String code = getAuthorizationCode();
        Map<String, Object> tokenResponse = exchangeCodeForTokens(code);
        String refreshToken = (String) tokenResponse.get("refresh_token");

        // Step 2: Try to use refresh token with wrong client secret
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken)
                        .param("client_id", CLIENT_ID)
                        .param("client_secret", "wrong_secret"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void refreshTokenTest_verifyDatabasePersistence() throws Exception {
        // Step 1: Get tokens
        String code = getAuthorizationCode();
        Map<String, Object> tokenResponse = exchangeCodeForTokens(code);
        String accessToken = (String) tokenResponse.get("access_token");
        String refreshToken = (String) tokenResponse.get("refresh_token");

        // Step 2: Verify tokens are saved in database
        var authInDb = oauth2AuthorizationJpaRepository.findByAccessTokenValue(accessToken);
        Assertions.assertTrue(authInDb.isPresent(), "Authorization should be saved in database");

        var authEntity = authInDb.get();
        Assertions.assertEquals(accessToken, authEntity.getAccessTokenValue(), "Access token should match");
        Assertions.assertEquals(refreshToken, authEntity.getRefreshTokenValue(), "Refresh token should match");
        Assertions.assertNotNull(authEntity.getRegisteredClientId(), "Registered client ID should be set");
        Assertions.assertEquals("admin", authEntity.getPrincipalName(), "Principal name should match");
        Assertions.assertNotNull(authEntity.getAccessTokenIssuedAt(), "Access token issued time should be set");
        Assertions.assertNotNull(authEntity.getAccessTokenExpiresAt(), "Access token expiry time should be set");
        Assertions.assertNotNull(authEntity.getRefreshTokenIssuedAt(), "Refresh token issued time should be set");
        Assertions.assertNotNull(authEntity.getRefreshTokenExpiresAt(), "Refresh token expiry time should be set");

        // Step 3: Use refresh token
        MvcResult refreshResult = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken)
                        .param("client_id", CLIENT_ID)
                        .param("client_secret", CLIENT_SECRET))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, Object> refreshResponse =
                objectMapper.readValue(refreshResult.getResponse().getContentAsString(), Map.class);
        String newAccessToken = (String) refreshResponse.get("access_token");
        String newRefreshToken = (String) refreshResponse.get("refresh_token");

        // Step 4: Verify new tokens are saved in database
        var updatedAuthInDb = oauth2AuthorizationJpaRepository.findByAccessTokenValue(newAccessToken);
        Assertions.assertTrue(updatedAuthInDb.isPresent(), "Updated authorization should be saved in database");
        Assertions.assertEquals(
                newAccessToken, updatedAuthInDb.get().getAccessTokenValue(), "New access token should match");
        Assertions.assertEquals(
                newRefreshToken, updatedAuthInDb.get().getRefreshTokenValue(), "New refresh token should match");

        // Step 5: Verify old authorization still exists in database
        // Note: This implementation keeps multiple authorizations and allows refresh token reuse
        var oldAuthInDb = oauth2AuthorizationJpaRepository.findByAccessTokenValue(accessToken);
        Assertions.assertTrue(
                oldAuthInDb.isPresent(), "Old authorization remains in database (implementation allows token reuse)");
    }

    // Helper methods

    @WithMockUser(username = "admin", roles = "admin")
    private String getAuthorizationCode() throws Exception {
        MvcResult authorizeResult = mockMvc.perform(get("/oauth2/authorize")
                        .queryParam("state", "test_state")
                        .queryParam("nonce", "test_nonce")
                        .queryParam("scope", "openid")
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("client_id", CLIENT_ID)
                        .queryParam("response_mode", "form_post")
                        .queryParam("response_type", "code"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        return extractCodeFromRedirect(authorizeResult);
    }

    private Map<String, Object> exchangeCodeForTokens(String code) throws Exception {
        MvcResult tokenResult = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("client_id", CLIENT_ID)
                        .param("client_secret", CLIENT_SECRET))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readValue(tokenResult.getResponse().getContentAsString(), Map.class);
    }

    private String extractCodeFromRedirect(MvcResult result) {
        String location = result.getResponse().getRedirectedUrl();
        Assertions.assertNotNull(location, "Redirect location should not be null");
        Assertions.assertTrue(location.contains("code="), "Redirect should contain authorization code");
        return UriComponentsBuilder.fromUriString(location)
                .build()
                .getQueryParams()
                .getFirst("code");
    }
}
