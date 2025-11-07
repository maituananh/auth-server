package com.vn.anhmt.authentication.store.mapper;

import com.vn.anhmt.authentication.entity.OAuth2AuthorizationConsentEntity;
import java.util.Set;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.StringUtils;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class OAuth2AuthorizationConsentStoreMapper {

    public static OAuth2AuthorizationConsentEntity toEntity(OAuth2AuthorizationConsent authorizationConsent) {
        OAuth2AuthorizationConsentEntity entity = new OAuth2AuthorizationConsentEntity();
        entity.setRegisteredClientId(authorizationConsent.getRegisteredClientId());
        entity.setPrincipalName(authorizationConsent.getPrincipalName());

        Set<String> authorities = authorizationConsent.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(java.util.stream.Collectors.toSet());
        entity.setAuthorities(StringUtils.collectionToDelimitedString(authorities, ","));

        return entity;
    }

    public static OAuth2AuthorizationConsent toObject(
            OAuth2AuthorizationConsentEntity entity, RegisteredClient registeredClient) {
        String principalName = entity.getPrincipalName();
        OAuth2AuthorizationConsent.Builder builder =
                OAuth2AuthorizationConsent.withId(entity.getRegisteredClientId(), principalName);

        if (entity.getAuthorities() != null) {
            for (String authority : StringUtils.commaDelimitedListToSet(entity.getAuthorities())) {
                builder.authority(new SimpleGrantedAuthority(authority));
            }
        }

        return builder.build();
    }
}
