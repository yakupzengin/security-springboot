/*
    This class represents the request model for user registration.
    It contains fields for the user's first name, last name, email, and password.

 */
package com.yzengin.security.auth;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {

    private String firstname;
    private String lastname;
    private String email;
    private String password;
}
