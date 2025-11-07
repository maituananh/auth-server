package com.vn.anhmt.authentication.domain;

import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Token {

    private UUID id;
    private boolean isLogout;
    private String accessToken;
    private String refreshToken;
}
