package com.vn.anhmt.authentication.repository;

import com.vn.anhmt.authentication.entity.TokenEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.repository.CrudRepository;

public interface TokenRepository extends CrudRepository<TokenEntity, UUID> {

    Optional<TokenEntity> findByAccessToken(final String accessToken);
}
