package com.vn.anhmt.authentication.repository;

import com.vn.anhmt.authentication.entity.Oauth2RegisteredClientEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OAuth2RegisteredClientJpaRepository extends JpaRepository<Oauth2RegisteredClientEntity, String> {

    Optional<Oauth2RegisteredClientEntity> findByClientId(final String clientId);
}
