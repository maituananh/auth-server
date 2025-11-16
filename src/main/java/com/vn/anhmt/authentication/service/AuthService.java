package com.vn.anhmt.authentication.service;

import com.vn.anhmt.authentication.controller.auth.dto.LogoutRequest;
import com.vn.anhmt.authentication.store.OAuth2AuthorizationStore;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuthService {

    private final OAuth2AuthorizationStore oAuth2AuthorizationStore;

    @Transactional
    public void logout(LogoutRequest logoutRequest) {
        final var oauth2 =
                oAuth2AuthorizationStore.findByToken(logoutRequest.getAccessToken(), OAuth2TokenType.ACCESS_TOKEN);

        if (oauth2 == null) {
            throw new AuthenticationServiceException("Token not found");
        }

        oAuth2AuthorizationStore.remove(oauth2);
        SecurityContextHolder.clearContext();
    }
}
