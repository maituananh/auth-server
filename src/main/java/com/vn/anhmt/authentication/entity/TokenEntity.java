package com.vn.anhmt.authentication.entity;

import java.util.UUID;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@RedisHash("tokens")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenEntity {

    @Id
    private UUID id;

    private boolean isLogout;
    private String accessToken;
    private String refreshToken;
}
