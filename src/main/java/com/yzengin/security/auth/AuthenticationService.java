/*
     This class handles user authentication-related operations such as user registration and authentication.
     It interacts with the user repository for user data manipulation, password encoder for password hashing,
     JWT service for token generation and validation, and authentication manager for user authentication.

 */
package com.yzengin.security.auth;

import com.yzengin.security.config.JwtService;
import com.yzengin.security.user.Role;
import com.yzengin.security.user.User;
import com.yzengin.security.user.UserRepository;
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

    /*
        Registers a new user with the provided registration request.
        Creates a new user entity, saves it to the repository, generates an authentication token
        and returns it as part of the response.

     */
    public AuthenticationResponse register(RegisterRequest request) {
        // Create a new user entity with the provided details and encode the password.

        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword( )))
                .role(Role.USER)
                .build();
        repository.save(user);

        // Generate an authentication token for the registered user.
        var jwtToken =jwtService.generateToken(user);

        // Build and return the authentication response containing the token.
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    /*
        Authenticates a user with the provided authentication request.
        Attempts to authenticate the user with the authentication manager, retrieves the user details,
        generates an authentication token, and returns it as part of the response.

     */
    public AuthenticationResponse authenticate(AuthenticationRequest request) {

        // Authenticate the user with the provided credentials using the authentication manager.
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                ));
        var user = repository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken =jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
