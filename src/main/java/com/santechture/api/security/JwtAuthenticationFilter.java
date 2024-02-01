package com.santechture.api.security;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        if (username == null || username.isEmpty()) {
            throw new BadCredentialsException("Username cannot be empty");
        }
        String password = request.getParameter("password");
        if (password == null || password.isEmpty()) {
            throw new BadCredentialsException("Password cannot be empty");
        }
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password, new ArrayList<>());

        try {
            return authenticationManager.authenticate(authenticationToken);
        } catch (AuthenticationException e) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return null;
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        String username = authResult.getName();
        try {
            String token = Jwts.builder()
                    .setSubject(username)
                    .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 1000))
                    .signWith(SignatureAlgorithm.HS512, "fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8") // Replace with your secure secret
                    .compact();
            response.addHeader("Authorization", "Bearer " + token);
        } catch (Exception e) {
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }
}