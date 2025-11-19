package com.vn.anhmt.authentication;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

class AuthorizationCodePKCEIntegrationTest extends BaseIntegrationTest {

    private static final String CLIENT_ID = "client-pkce";
    private static final String REDIRECT_URI = "https://oauthdebugger.com/debug";

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void authorizationCodePKCETest() throws Exception {
        // Verify client was created
        var client = oauth2RegisteredClientJpaRepository.findByClientId(CLIENT_ID);
        Assertions.assertTrue(client.isPresent(), "Client should be registered");

        // Generate PKCE code verifier and challenge
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);

        // Step 1: Authorization request with PKCE parameters (only request 'openid' to avoid consent page)
        MvcResult authorizeResult = mockMvc.perform(get("/oauth2/authorize")
                        .queryParam("state", "5dv9oybwdo3")
                        .queryParam("nonce", "p28dqdns7m")
                        .queryParam("scope", "openid")
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("client_id", CLIENT_ID)
                        .queryParam("response_mode", "form_post")
                        .queryParam("response_type", "code")
                        .queryParam("code_challenge", codeChallenge)
                        .queryParam("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String location = authorizeResult.getResponse().getRedirectedUrl();
        assert location != null && location.contains("code=");
        String code = UriComponentsBuilder.fromUriString(location)
                .build()
                .getQueryParams()
                .getFirst("code");

        Assertions.assertNotNull(code);

        // Step 2: Token request with code_verifier (no client_secret needed for public clients)
        MvcResult tokenResult = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("client_id", CLIENT_ID)
                        .param("code_verifier", codeVerifier))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, Object> tokenResponse =
                objectMapper.readValue(tokenResult.getResponse().getContentAsString(), Map.class);

        String accessToken = (String) tokenResponse.get("access_token");
        Assertions.assertNotNull(accessToken);

        // Step 3: Use access token to get user info
        mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").exists());
    }

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void authorizationCodePKCETest_withInvalidCodeVerifier_shouldFail() throws Exception {
        // Generate PKCE code verifier and challenge
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);

        // Step 1: Authorization request with PKCE parameters
        MvcResult authorizeResult = mockMvc.perform(get("/oauth2/authorize")
                        .queryParam("state", "5dv9oybwdo3")
                        .queryParam("nonce", "p28dqdns7m")
                        .queryParam("scope", "openid")
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("client_id", CLIENT_ID)
                        .queryParam("response_mode", "form_post")
                        .queryParam("response_type", "code")
                        .queryParam("code_challenge", codeChallenge)
                        .queryParam("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String location = authorizeResult.getResponse().getRedirectedUrl();
        assert location != null && location.contains("code=");
        String code = UriComponentsBuilder.fromUriString(location)
                .build()
                .getQueryParams()
                .getFirst("code");

        Assertions.assertNotNull(code);

        // Step 2: Token request with WRONG code_verifier - should fail
        String wrongCodeVerifier = generateCodeVerifier();
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("client_id", CLIENT_ID)
                        .param("code_verifier", wrongCodeVerifier))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void authorizationCodePKCETest_withoutCodeChallenge_shouldFail() throws Exception {
        // Step 1: Authorization request WITHOUT PKCE parameters - should fail because client requires PKCE
        MvcResult result = mockMvc.perform(get("/oauth2/authorize")
                        .queryParam("state", "5dv9oybwdo3")
                        .queryParam("nonce", "p28dqdns7m")
                        .queryParam("scope", "openid")
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("client_id", CLIENT_ID)
                        .queryParam("response_mode", "form_post")
                        .queryParam("response_type", "code"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        // Verify that the redirect contains an error parameter
        String location = result.getResponse().getRedirectedUrl();
        Assertions.assertNotNull(location);
        Assertions.assertTrue(
                location.contains("error=invalid_request"), "Expected error=invalid_request in redirect URL");
        Assertions.assertTrue(
                location.contains("code_challenge"), "Expected error description to mention code_challenge");
    }

    /**
     * Generate a cryptographically random code verifier
     * According to RFC 7636, code verifier should be a random string between 43-128 characters
     */
    private String generateCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifier = new byte[32];
        secureRandom.nextBytes(codeVerifier);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
    }

    /**
     * Generate code challenge from code verifier using S256 method (SHA-256)
     */
    private String generateCodeChallenge(String codeVerifier) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
}
