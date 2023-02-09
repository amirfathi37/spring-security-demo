package com.amir.springsecurity.controllers;

import com.amir.springsecurity.dto.AuthenticationRequest;
import com.amir.springsecurity.dto.AuthenticationResponse;
import com.amir.springsecurity.dto.RegisterRequest;
import com.amir.springsecurity.services.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class authController {
    private final AuthService authService;

    @PostMapping("/register")
    ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));

    }

    @PostMapping("/authenticate")
    ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) throws Exception {

        return ResponseEntity.ok(authService.authenticate(request));
    }
}
