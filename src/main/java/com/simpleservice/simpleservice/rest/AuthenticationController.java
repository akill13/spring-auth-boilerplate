package com.simpleservice.simpleservice.rest;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.simpleservice.simpleservice.security.jwt.JWTFilter;
import com.simpleservice.simpleservice.security.jwt.TokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthenticationController {
    private TokenProvider tokenProvider;
    private AuthenticationManagerBuilder authenticationManagerBuilder;

    @Autowired
    public AuthenticationController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider=tokenProvider;
        this.authenticationManagerBuilder=authenticationManagerBuilder;
    }

    @PostMapping("/auth")
    public ResponseEntity<JWTToken> authorize(@RequestBody Map<String, Object> payload) {
        System.out.println(payload);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(payload.get("username"),payload.get("password"));
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        boolean rememberMe = true;
        String jwt = tokenProvider.createToken(authentication, rememberMe);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JWTFilter.AUTHORIZATION_HEADER,"Bearer "+jwt);

        return new ResponseEntity<>(new JWTToken(jwt), httpHeaders, HttpStatus.OK);

    }

    static class JWTToken {

        private String idToken;

        JWTToken(String idToken) {
            this.idToken = idToken;
        }

        @JsonProperty("id_token")
        String getIdToken() {
            return idToken;
        }

        void setIdToken(String idToken) {
            this.idToken = idToken;
        }
    }
}
