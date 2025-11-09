package com.vn.anhmt.authentication.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/test")
public class Oauth2TestController {

    @GetMapping
    public String login() {
        return "Authorization code received";
    }
}
