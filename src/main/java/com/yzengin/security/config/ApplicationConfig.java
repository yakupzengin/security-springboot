/*
    This class provides the configuration for the application, including user authentication and password encoding.

    - @Configuration: Indicates that this class provides Spring application configuration.
    - @RequiredArgsConstructor: Lombok annotation generating a constructor with required arguments.
    - @Bean: Indicates that a method produces a bean to be managed by the Spring container.

    - userDetailsService(): Bean method creating a UserDetailsService bean, which retrieves user details from the
    database.
    - authenticationProvider(): Bean method creating an AuthenticationProvider bean, which authenticates users
    using UserDetails.
    - authenticationManager(): Bean method creating an AuthenticationManager bean, which authenticates users
    during the login process.
    - passwordEncoder(): Bean method creating a PasswordEncoder bean, which encodes and verifies passwords securely.

    Note: BCryptPasswordEncoder is used for password encoding, and DaoAuthenticationProvider is used for user authentication.
*/
package com.yzengin.security.config;

import com.yzengin.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository repository;

    @Bean
    public UserDetailsService userDetailsService(){
        return username -> repository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found."));
    }

    @Bean
    public AuthenticationProvider authenticationProvider( ){
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
