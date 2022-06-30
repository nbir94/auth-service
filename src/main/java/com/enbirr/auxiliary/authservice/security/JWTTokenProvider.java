package com.enbirr.auxiliary.authservice.security;

import com.enbirr.auxiliary.authservice.dto.AuthServiceResponseDto;
import com.enbirr.auxiliary.authservice.exception.UnauthorizedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import javax.crypto.SecretKey;

@Service
public class JWTTokenProvider {

  @Value("${auth.basic.username}")
  private String expectedUsername;
  @Value("${auth.basic.password}")
  private String expectedPassword;
  @Value("${auth.jwt.secret-key}")
  private String secretKey;
  @Value("${auth.jwt.lifetime-seconds}")
  private Integer lifetimeSeconds;

  public AuthServiceResponseDto getJWTToken(String authHeader) {
    byte[] bytes = Base64.getDecoder().decode(authHeader.replace("Basic ", ""));
    String[] credentials = new String(bytes, StandardCharsets.UTF_8).split(":");
    String username = credentials[0];
    String password = credentials[1];

    if (!expectedUsername.equals(username) || !expectedPassword.equals(password)) {
      throw new UnauthorizedException("Username and password are not valid");
    }
    SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

    Date expiration = new Date(System.currentTimeMillis() + lifetimeSeconds * 1000);
    String token = Jwts
        .builder()
        .setId("auth-app")
        .setSubject(username)
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(expiration)
        .signWith(key, SignatureAlgorithm.HS512)
        .compact();

    AuthServiceResponseDto result = new AuthServiceResponseDto();
    result.setType("Bearer");
    result.setValue(token);
    result.setExpiry(expiration.getTime());
    return result;
  }

  public void validateToken(String authHeader) {
    if (!authHeader.startsWith("Bearer ")) {
      throw new UnauthorizedException("Wrong Authentication header");
    }
    String token = authHeader.substring(7);
    Claims tokenBody = null;
    try {
      tokenBody = Jwts.parserBuilder()
          .setSigningKey(secretKey.getBytes())
          .build()
          .parseClaimsJws(token)
          .getBody();
    } catch (Exception e) {
      throw new UnauthorizedException("Unable to parse token due to error: " + e.getMessage());
    }
    if (!expectedUsername.equals(tokenBody.getSubject())) {
      throw new UnauthorizedException("Unknown username in token");
    }


  }
}
