package com.vn.anhmt.authentication.store.mapper;

import com.vn.anhmt.authentication.domain.Token;
import com.vn.anhmt.authentication.entity.TokenEntity;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class TokenStoreMapper {

    public static Optional<Token> toToken(final TokenEntity tokenEntity) {
        if (tokenEntity == null) {
            return Optional.empty();
        }

        return Optional.of(Token.builder()
                .accessToken(tokenEntity.getAccessToken())
                .refreshToken(tokenEntity.getRefreshToken())
                .id(tokenEntity.getId())
                .isLogout(tokenEntity.isLogout())
                .build());
    }
}
