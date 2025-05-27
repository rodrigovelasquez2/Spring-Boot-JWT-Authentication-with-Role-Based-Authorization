package com.velasquez.authentication.demo.service;

import com.velasquez.authentication.demo.entity.Role;
import com.velasquez.authentication.demo.entity.Users;
import com.velasquez.authentication.demo.entity.dto.AuthenticationRequest;
import com.velasquez.authentication.demo.entity.dto.AuthenticationResponse;
import com.velasquez.authentication.demo.entity.dto.RegisterRequest;
import com.velasquez.authentication.demo.jwt.JwtService;
import com.velasquez.authentication.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        // Obtener el rol del request o usar ROLE_USER por defecto
        Role userRole = request.getRole();
        if (userRole == null) {
            userRole = Role.ROLE_USER; // Valor por defecto
        }

        var user = Users.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(userRole)
                .build();
        repository.save(user);

        var jwtToken =jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository
                .findByEmail(request.getEmail())
                .orElseThrow();

        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
