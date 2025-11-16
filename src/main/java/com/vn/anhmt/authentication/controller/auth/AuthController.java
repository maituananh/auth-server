package com.vn.anhmt.authentication.controller.auth;

import com.vn.anhmt.authentication.controller.auth.dto.LogoutRequest;
import com.vn.anhmt.authentication.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("oauth2")
public class AuthController {

    private final AuthService authService;

    @PostMapping(path = "/logout", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<String> logout(LogoutRequest logoutRequest) {
        authService.logout(logoutRequest);

        return new ResponseEntity<>("Logout success", HttpStatusCode.valueOf(200));
    }
}
