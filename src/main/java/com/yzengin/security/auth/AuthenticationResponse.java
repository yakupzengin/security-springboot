/*
    This class represents the response model for user authentication, providing structured
    data for communication between the client and server during authentication processes.
    It encapsulates information about the authentication token returned to the client upon
    successful authentication.


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
public class AuthenticationResponse {
    private String token;

}
