package com.vn.anhmt.authentication.repository;

import com.vn.anhmt.authentication.entity.OAuth2AuthorizationEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface OAuth2AuthorizationJpaRepository extends JpaRepository<OAuth2AuthorizationEntity, String> {

    Optional<OAuth2AuthorizationEntity> findByState(String state);

    Optional<OAuth2AuthorizationEntity> findByAuthorizationCodeValue(String authorizationCode);

    Optional<OAuth2AuthorizationEntity> findByAccessTokenValue(String accessToken);

    Optional<OAuth2AuthorizationEntity> findByRefreshTokenValue(String refreshToken);

    Optional<OAuth2AuthorizationEntity> findByOidcIdTokenValue(String idToken);

    Optional<OAuth2AuthorizationEntity> findByUserCodeValue(String userCode);

    Optional<OAuth2AuthorizationEntity> findByDeviceCodeValue(String deviceCode);

    @Query("select a from OAuth2AuthorizationEntity a where a.state = :token"
            + " or a.authorizationCodeValue = :token"
            + " or a.accessTokenValue = :token"
            + " or a.refreshTokenValue = :token"
            + " or a.oidcIdTokenValue = :token"
            + " or a.userCodeValue = :token"
            + " or a.deviceCodeValue = :token")
    Optional<OAuth2AuthorizationEntity>
            findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(
                    @Param("token") String token);
}
