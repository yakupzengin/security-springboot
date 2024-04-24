package com.yzengin.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // Secret key used for JWT generation and validation
    private static final String SECRET_KEY ="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";


    // Extracts username from JWT token
    public String extractUsername(String token) {
        return extractClaim(token,Claims::getSubject);
    }


    // Extracts a specific claim from JWT token using provided function
    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Generates JWT token for a given UserDetails object
    public String generateToken(
            UserDetails userDetails
    ) {
        return generateToken(new HashMap<>(),userDetails);
    }

    // Generates JWT token with additional claims for a given UserDetails object
    public String generateToken(
            Map<String,Object> extraClaims,
            UserDetails userDetails
    ){
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Checks if the provided token is valid for the given UserDetails
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // Checks if the provided token is expired
    private boolean isTokenExpired(String token) {
        return extrackExpiration(token).before(new Date());
    }

    // Extracts expiration date from JWT token
    private Date extrackExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }

    // Extracts all claims from JWT token
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // Retrieves the signing key used for JWT generation and validation
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
