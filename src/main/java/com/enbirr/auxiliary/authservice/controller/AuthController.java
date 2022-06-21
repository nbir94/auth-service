package com.enbirr.auxiliary.authservice.controller;

import com.enbirr.auxiliary.authservice.dto.AuthServiceResponseDto;
import com.enbirr.auxiliary.authservice.security.JWTTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

  private final JWTTokenProvider tokenProvider;

  /**
   * Returns token if Basic Auth credentials in header are valid
   * @param authHeader expects header with Basic Auth credentials
   * @return DTO with token
   */
  @GetMapping("/token")
  public AuthServiceResponseDto getToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
    return tokenProvider.getJWTToken(authHeader);
  }
}
