package com.sp.fc.web.config;


import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RequestInfo {

  private String remoteIp;
  private String sessionId;
  private LocalDateTime LoginTime;
}
