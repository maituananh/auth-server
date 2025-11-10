package com.vn.anhmt.authentication.configuration.custom.token;

import static com.nimbusds.jwt.JWTClaimNames.SUBJECT;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.TOKEN_TYPE_HINT;

import java.util.HashMap;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
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

        OAuth2Authorization oAuth2Authorization = context.getAuthorization();

        if (oAuth2Authorization != null) {
            claims.put(SUBJECT, oAuth2Authorization.getPrincipalName());
            //            claims.put(
            //                    "roles",
            //                    oAuth2Authorization.getAuthorities().stream()
            //                            .map(GrantedAuthority::getAuthority)
            //                            .toList());
        }

        context.getClaims().claims(c -> c.putAll(claims));
    }
}
