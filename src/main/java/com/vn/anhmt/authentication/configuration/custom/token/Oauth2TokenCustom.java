package com.vn.anhmt.authentication.configuration.custom.token;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.TOKEN_TYPE_HINT;

import com.vn.anhmt.authentication.configuration.custom.user.UserDetailsCustom;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

@Component
public class Oauth2TokenCustom implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(final JwtEncodingContext context) {
        Authentication principal = context.getPrincipal();

        Map<String, Object> claims = new HashMap<>();
        claims.put("client_id", context.getRegisteredClient().getClientId());
        claims.put(TOKEN_TYPE_HINT, context.getTokenType().getValue());

        if (principal.getPrincipal() instanceof UserDetailsCustom user) {
            claims.put("user_id", user.getId());
            claims.put(
                    "roles",
                    user.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .toList());
        }

        context.getClaims().claims(c -> c.putAll(claims));
    }
}
