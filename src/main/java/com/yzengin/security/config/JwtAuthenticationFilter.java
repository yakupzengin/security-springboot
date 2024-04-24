/*
    This class implements a filter to authenticate users using JSON Web Tokens (JWT).

    - JwtAuthenticationFilter: Extends OncePerRequestFilter to ensure a single execution per request.
    - doFilterInternal(): Method overriding the core filter logic to extract and validate JWT tokens.

    - jwtService: An instance of JwtService for JWT token extraction and validation.
    - userDetailsService: An instance of UserDetailsService to load user details by username/email.

    The filter checks the Authorization header of incoming requests for a JWT token.
    If a valid token is found, it extracts the user email from the token using JwtService.
    Then, it loads user details from the database using UserDetailsService.
    If the token is valid and the user details are found, it creates an authentication token
    using UsernamePasswordAuthenticationToken and updates the SecurityContextHolder with the authentication token.
    The filter chain continues after authentication.

*/
package com.yzengin.security.config;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter  {

    private final JwtService jwtService;
    private final UserDetailsService  userDetailsService;



    // Authentication filter to validate JWT token and extract user information.
    // JWT token is extracted from the Authorization header of the HTTP request.
    // If no token is present or the format is incorrect, the filter chain continues without authentication.

    @Override
    protected void doFilterInternal(
            @Nonnull HttpServletRequest request,
            @Nonnull HttpServletResponse response,
            @Nonnull FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request,response);
            return;
        }
        jwt = authHeader.substring(7);

        // Extracting user email from JWT token using JwtService
        userEmail = jwtService.extractUsername(jwt);

        if (userEmail !=null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            if (jwtService.isTokenValid(jwt,userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // Update the securityContextHolder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request,response);
    }
}
