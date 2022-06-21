package com.enbirr.auxiliary.authservice.controller;

import com.enbirr.auxiliary.authservice.security.JWTTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class ReceiverController {

  private final JWTTokenProvider tokenProvider;

  /**
   * Prints content of the request body in log if request was successfully authenticated
   * @param auth Bearer token given by method in AuthController
   * @param body any request body
   * @return OK (200) if data was published
   */
  @PostMapping("/publish")
  public ResponseEntity<String> publishData (
      @RequestHeader(HttpHeaders.AUTHORIZATION) String auth,
      @RequestBody String body
  ) {
    tokenProvider.validateToken(auth);
    log.info("Received and successfully authenticated HTTP request with body: \n{}", body);
    return ResponseEntity.ok("Published");
  }
}
