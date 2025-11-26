package com.vn.anhmt.authentication.controller.user.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.UUID;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserResponse {

    private UUID id;
    private String username;
}
