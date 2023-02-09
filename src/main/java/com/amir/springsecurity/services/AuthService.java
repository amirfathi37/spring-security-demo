package com.amir.springsecurity.services;

import com.amir.springsecurity.config.JwtService;
import com.amir.springsecurity.dto.AuthenticationRequest;
import com.amir.springsecurity.dto.AuthenticationResponse;
import com.amir.springsecurity.dto.RegisterRequest;
import com.amir.springsecurity.user.Role;
import com.amir.springsecurity.user.User;
import com.amir.springsecurity.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder().firstName(request.getName()).lastName(request.getFamily()).email(request.getEmail()).password(passwordEncoder.encode(request.getPassword())).role(Role.USER).build();

        userRepository.save(user);
        return AuthenticationResponse.builder().token(jwtService.generateToken(user)).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) throws Exception {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();

        return AuthenticationResponse.builder().token(jwtService.generateToken(user)).build();
    }
}
