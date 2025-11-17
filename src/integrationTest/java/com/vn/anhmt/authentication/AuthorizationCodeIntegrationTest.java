package com.vn.anhmt.authentication;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.vn.anhmt.authentication.repository.OAuth2RegisteredClientJpaRepository;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

class AuthorizationCodeIntegrationTest extends BaseIntegrationTest {

    private static final String CLIENT_ID = "client";
    private static final String CLIENT_SECRET = "secret";
    private static final String REDIRECT_URI = "https://oauthdebugger.com/debug";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private OAuth2RegisteredClientJpaRepository oauth2RegisteredClientJpaRepository;

    @Test
    @WithMockUser(username = "admin", roles = "admin")
    void authorizationCodeTest() throws Exception {
        // Verify client was created
        var client = oauth2RegisteredClientJpaRepository.findByClientId(CLIENT_ID);
        Assertions.assertTrue(client.isPresent(), "Client should be registered");

        MvcResult authorizeResult = mockMvc.perform(get("/oauth2/authorize")
                        .queryParam("state", "5dv9oybwdo3")
                        .queryParam("nonce", "p28dqdns7m")
                        .queryParam("scope", "openid")
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("client_id", CLIENT_ID)
                        .queryParam("response_mode", "form_post")
                        .queryParam("response_type", "code"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String location = authorizeResult.getResponse().getRedirectedUrl();
        assert location != null && location.contains("code=");
        String code = UriComponentsBuilder.fromUriString(location)
                .build()
                .getQueryParams()
                .getFirst("code");

        Assertions.assertNotNull(code);

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
        Assertions.assertNotNull(accessToken);

        mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").exists());
    }
}
