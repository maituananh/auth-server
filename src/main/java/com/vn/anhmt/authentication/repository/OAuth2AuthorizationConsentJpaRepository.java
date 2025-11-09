package com.vn.anhmt.authentication.repository;

import com.vn.anhmt.authentication.entity.OAuth2AuthorizationConsentEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OAuth2AuthorizationConsentJpaRepository
        extends JpaRepository<
                OAuth2AuthorizationConsentEntity, OAuth2AuthorizationConsentEntity.AuthorizationConsentId> {

    Optional<OAuth2AuthorizationConsentEntity> findByRegisteredClientIdAndPrincipalName(
            String registeredClientId, String principalName);

    void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}
