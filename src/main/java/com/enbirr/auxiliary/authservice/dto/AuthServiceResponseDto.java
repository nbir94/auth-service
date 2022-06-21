package com.enbirr.auxiliary.authservice.dto;

import lombok.Data;

@Data
public class AuthServiceResponseDto {
  private String type;
  private String value;
  private Long expiry;
}
