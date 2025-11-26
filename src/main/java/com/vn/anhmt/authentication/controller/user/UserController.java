package com.vn.anhmt.authentication.controller.user;

import com.vn.anhmt.authentication.controller.user.dto.UserResponse;
import com.vn.anhmt.authentication.domain.User;
import com.vn.anhmt.authentication.service.UserService;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        List<User> users = userService.getAllUsers();
        List<UserResponse> userResponses = users.stream()
                .map(user -> UserResponse.builder()
                        .id(user.getId())
                        .username(user.getUsername())
                        .build())
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(userResponses);
    }
}
