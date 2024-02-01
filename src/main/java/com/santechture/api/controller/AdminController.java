package com.santechture.api.controller;


import com.santechture.api.dto.GeneralResponse;
import com.santechture.api.exception.BusinessExceptions;
import com.santechture.api.service.AdminService;
import com.santechture.api.validation.LoginRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;

@RestController
@RequestMapping(path = "admin")
public class AdminController {

    private final AdminService adminService;
    private final AuthenticationManager authenticationManager;

    public AdminController(AdminService adminService, AuthenticationManager authenticationManager) {
        this.adminService = adminService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping
    public ResponseEntity<GeneralResponse> login(@RequestBody LoginRequest request) throws BusinessExceptions {
        try {
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            String username = authentication.getName();
            String token = generateJwtToken(username); // Replace with your JWT generation logic
            HttpHeaders responseHeaders = new HttpHeaders();
            responseHeaders.add("Authorization", "Bearer " + token);

            return ResponseEntity.ok().headers(responseHeaders).body(adminService.login(request).getBody());

        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    private String generateJwtToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 1000))
                .signWith(SignatureAlgorithm.HS512, "fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8fj3o8fj9w8")
                .compact();
    }
}