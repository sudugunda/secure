package com.security.secure.jwt;

import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.awt.*;
import java.net.*;
import java.security.AlgorithmConstraints;
import java.security.cert.Certificate;


@Configuration
public class JwtSecretKey {

    private final JwtConfig jwtConfig;

    @Autowired
    public JwtSecretKey(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }


    @Bean
    public SecretKey secretKey(){
        return Keys.hmacShaKeyFor(jwtConfig.getSecretKey().getBytes());
    }
}
