package com.vn.anhmt.authentication.configuration.custom.user;

import com.vn.anhmt.authentication.domain.User;
import com.vn.anhmt.authentication.store.UserStore;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserInfoServiceCustom {

    private final UserStore userStore;

    public OidcUserInfo loadUser(String username) {
        final var user = userStore.findByUsername(username).orElseThrow();
        return new OidcUserInfo(toOidcUserInfo(user));
    }

    private Map<String, Object> toOidcUserInfo(final User user) {
        return OidcUserInfo.builder()
                .subject(user.getUsername())
                .claim("user_id", user.getId())
                .emailVerified(true)
                .build()
                .getClaims();
    }
}
