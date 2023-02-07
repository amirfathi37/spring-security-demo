package com.amir.springsecurity.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String securityKey = "2A462D4A614E645267556B58703273357638792F423F4428472B4B6250655368";


    /*Part of generate token*/
    public String generateToken(Map<String, Object> extraClaimes, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaimes)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 24 * 60))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public boolean isValidToken(String token , UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isExpiredToken(token);
    }

    private boolean isExpiredToken(String token) {
        return extractExpreDateFromToken(token).before(new Date());
    }

    private Date extractExpreDateFromToken(String token) {
        return extractClaim(token , Claims::getExpiration);
    }
    /*Part of generate token*/

    /* Part of extract username from was sent token*/
    public String extractUsername(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }

    private Claims getAllClaimes(String jwtToken) {
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

    private <T> T extractClaim(String jwtTokon, Function<Claims, T> claimResolver) {
        Claims claims = getAllClaimes(jwtTokon);
        return claimResolver.apply(claims);
    }

    /* Part of extract username from was sent token*/
}
