package com.vn.anhmt.authentication.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("login/oauth2/code/client")
public class Oauth2Controller {

    @GetMapping
    public String login() {
        return "Authorization code received";
    }
}
