package com.vn.anhmt.authentication.configuration.custom.token;

import static com.nimbusds.jwt.JWTClaimNames.SUBJECT;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.TOKEN_TYPE_HINT;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

@Component
public class Oauth2TokenCustom implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(final JwtEncodingContext context) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("client_id", context.getRegisteredClient().getClientId());
        claims.put(TOKEN_TYPE_HINT, context.getTokenType().getValue());

        Authentication principal = context.getPrincipal();

        if (Objects.equals(context.getTokenType().getValue(), "access_token")
                && principal instanceof UsernamePasswordAuthenticationToken) {
            Set<String> authorities = principal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            context.getClaims().claim("authorities", authorities);

            //            UserDetailsCustom user = (UserDetailsCustom) principal.getPrincipal();
            //                    context.getClaims().claim("user", user);
        }

        OAuth2Authorization oAuth2Authorization = context.getAuthorization();

        if (oAuth2Authorization != null) {
            String principalName = oAuth2Authorization.getPrincipalName();

            claims.put(SUBJECT, principalName);
            claims.put("register_client_id", oAuth2Authorization.getRegisteredClientId());
        }

        context.getClaims().claims(c -> c.putAll(claims));
    }
}
