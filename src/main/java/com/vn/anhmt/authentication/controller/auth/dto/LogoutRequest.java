package com.vn.anhmt.authentication.controller.auth.dto;

import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LogoutRequest {
    private String accessToken;
    private String tokenTypeHint;
}
