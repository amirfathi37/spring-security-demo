package com.amir.springsecurity.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Base64;

@Service
public class JwtService {

    private static final String securityKey = "2A462D4A614E645267556B58703273357638792F423F4428472B4B6250655368";
    public String extractUsername(String jwtToken) {
        return null;
    }

    private Claims getAllClaimes(String jwtToken){
        JwtParserBuilder jwtParserBuilder = Jwts.parserBuilder();
        jwtParserBuilder.setSigningKey(getSignInKey());
        JwtParser build = jwtParserBuilder.build();
        Jwt parse = build.parse(jwtToken);
        Object body = parse.getBody();
        return (Claims) body;
    }

    private Key getSignInKey() {
        byte[] decode = Decoders.BASE64.decode(securityKey);
        SecretKey secretKey = Keys.hmacShaKeyFor(decode);
        return secretKey;
    }
}
