package com.vn.anhmt.authentication;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
 * Integration tests for OAuth2 Logout functionality
 * Tests cover token revocation, database cleanup, and post-logout token validation
 */
class OAuth2LogoutIntegrationTest extends BaseIntegrationTest {

    private static final String CLIENT_ID = "client";
    private static final String CLIENT_SECRET = "secret";
    private static final String REDIRECT_URI = "https://oauthdebugger.com/debug";

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void logoutTest_successful() throws Exception {
        // Step 1: Get access token
        TokenPair tokens = getTokens();
        String accessToken = tokens.accessToken();
        String refreshToken = tokens.refreshToken();

        // Step 2: Verify access token works before logout
        mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").exists());

        // Step 3: Verify tokens exist in database
        var authBeforeLogout = oauth2AuthorizationJpaRepository.findByAccessTokenValue(accessToken);
        Assertions.assertTrue(authBeforeLogout.isPresent(), "Authorization should exist in database before logout");

        // Step 4: Perform logout
        mockMvc.perform(post("/oauth2/logout")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("accessToken", accessToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Logout success"));

        // Step 5: Verify access token no longer works after logout
        mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());

        // Step 6: Verify refresh token no longer works after logout
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken)
                        .param("client_id", CLIENT_ID)
                        .param("client_secret", CLIENT_SECRET))
                .andExpect(status().isBadRequest());

        // Step 7: Verify authorization is removed from database
        var authAfterLogout = oauth2AuthorizationJpaRepository.findByAccessTokenValue(accessToken);
        Assertions.assertFalse(
                authAfterLogout.isPresent(), "Authorization should be removed from database after logout");

        var authByRefreshToken = oauth2AuthorizationJpaRepository.findByRefreshTokenValue(refreshToken);
        Assertions.assertFalse(
                authByRefreshToken.isPresent(), "Authorization should not be findable by refresh token after logout");
    }

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void logoutTest_withInvalidToken_shouldFail() throws Exception {
        // Try to logout with an invalid token
        // Returns 401 because Spring Security rejects invalid tokens before reaching the controller
        mockMvc.perform(post("/oauth2/logout")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("accessToken", "invalid_token_12345"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void logoutTest_withEmptyToken_shouldFail() throws Exception {
        // Try to logout with empty token
        // Returns 401 because Spring Security rejects empty tokens before reaching the controller
        mockMvc.perform(post("/oauth2/logout")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("accessToken", ""))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void logoutTest_multipleTimesWithSameToken_shouldFailSecondTime() throws Exception {
        // Step 1: Get access token
        TokenPair tokens = getTokens();
        String accessToken = tokens.accessToken();

        // Step 2: First logout should succeed
        mockMvc.perform(post("/oauth2/logout")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("accessToken", accessToken))
                .andExpect(status().isOk());

        // Step 3: Second logout with same token should fail (token already revoked)
        // Returns 401 because the token is no longer valid after first logout
        mockMvc.perform(post("/oauth2/logout")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("accessToken", accessToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void logoutTest_verifyCompleteCleanup() throws Exception {
        // Step 1: Get tokens
        TokenPair tokens = getTokens();
        String accessToken = tokens.accessToken();
        String refreshToken = tokens.refreshToken();

        // Step 2: Verify all token-related data exists in database
        var authBefore = oauth2AuthorizationJpaRepository.findByAccessTokenValue(accessToken);
        Assertions.assertTrue(authBefore.isPresent(), "Authorization should exist before logout");

        var authEntity = authBefore.get();
        Assertions.assertNotNull(authEntity.getAccessTokenValue(), "Access token should be set");
        Assertions.assertNotNull(authEntity.getRefreshTokenValue(), "Refresh token should be set");
        Assertions.assertNotNull(authEntity.getAccessTokenIssuedAt(), "Access token issued time should be set");
        Assertions.assertNotNull(authEntity.getAccessTokenExpiresAt(), "Access token expiry should be set");

        // Step 3: Perform logout
        mockMvc.perform(post("/oauth2/logout")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("accessToken", accessToken))
                .andExpect(status().isOk());

        // Step 4: Verify complete removal from database (all queries should return empty)
        Assertions.assertFalse(
                oauth2AuthorizationJpaRepository
                        .findByAccessTokenValue(accessToken)
                        .isPresent(),
                "Should not find by access token");
        Assertions.assertFalse(
                oauth2AuthorizationJpaRepository
                        .findByRefreshTokenValue(refreshToken)
                        .isPresent(),
                "Should not find by refresh token");

        // Step 5: Verify the ID no longer exists
        Assertions.assertFalse(
                oauth2AuthorizationJpaRepository.findById(authEntity.getId()).isPresent(),
                "Authorization record should be completely deleted");
    }

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void logoutTest_doesNotAffectOtherUsersSessions() throws Exception {
        // Step 1: Get first user's tokens
        TokenPair user1Tokens = getTokens();
        String user1AccessToken = user1Tokens.accessToken();

        // Step 2: Get second user's tokens (simulated by getting another set of tokens)
        TokenPair user2Tokens = getTokens();
        String user2AccessToken = user2Tokens.accessToken();

        // Step 3: Verify both tokens work
        mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + user1AccessToken))
                .andExpect(status().isOk());
        mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + user2AccessToken))
                .andExpect(status().isOk());

        // Step 4: Logout user1
        mockMvc.perform(post("/oauth2/logout")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("accessToken", user1AccessToken))
                .andExpect(status().isOk());

        // Step 5: Verify user1's token no longer works
        mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + user1AccessToken))
                .andExpect(status().isUnauthorized());

        // Step 6: Verify user2's token still works
        mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + user2AccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").exists());

        // Step 7: Verify only user1's authorization is removed from database
        Assertions.assertFalse(
                oauth2AuthorizationJpaRepository
                        .findByAccessTokenValue(user1AccessToken)
                        .isPresent(),
                "User1's authorization should be removed");
        Assertions.assertTrue(
                oauth2AuthorizationJpaRepository
                        .findByAccessTokenValue(user2AccessToken)
                        .isPresent(),
                "User2's authorization should still exist");
    }

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void logoutTest_afterTokenRefresh() throws Exception {
        // Step 1: Get initial tokens
        TokenPair initialTokens = getTokens();
        String refreshToken = initialTokens.refreshToken();

        // Step 2: Use refresh token to get new tokens
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

        // Step 3: Verify new access token works
        mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + newAccessToken))
                .andExpect(status().isOk());

        // Step 4: Logout with new access token
        mockMvc.perform(post("/oauth2/logout")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("accessToken", newAccessToken))
                .andExpect(status().isOk());

        // Step 5: Verify new access token no longer works
        mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + newAccessToken))
                .andExpect(status().isUnauthorized());

        // Step 6: Verify new refresh token no longer works
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", newRefreshToken)
                        .param("client_id", CLIENT_ID)
                        .param("client_secret", CLIENT_SECRET))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void logoutTest_verifySecurityContextCleared() throws Exception {
        // Step 1: Get access token
        TokenPair tokens = getTokens();
        String accessToken = tokens.accessToken();

        // Step 2: Use the token to access a protected resource
        mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk());

        // Step 3: Logout (should clear security context)
        mockMvc.perform(post("/oauth2/logout")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("accessToken", accessToken))
                .andExpect(status().isOk());

        // Step 4: Verify token cannot be used anymore (context is cleared)
        mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
    }

    // Helper methods

    @WithMockUser(username = "admin", roles = "admin")
    private TokenPair getTokens() throws Exception {
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

        // Step 2: Exchange code for tokens
        MvcResult tokenResult = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("client_id", CLIENT_ID)
                        .param("client_secret", CLIENT_SECRET))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, Object> tokenResponse =
                objectMapper.readValue(tokenResult.getResponse().getContentAsString(), Map.class);
        String accessToken = (String) tokenResponse.get("access_token");
        String refreshToken = (String) tokenResponse.get("refresh_token");

        return new TokenPair(accessToken, refreshToken);
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

    private record TokenPair(String accessToken, String refreshToken) {}
}
