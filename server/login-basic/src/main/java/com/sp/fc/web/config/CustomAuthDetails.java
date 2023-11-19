package com.sp.fc.web.config;

import javax.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;


public class CustomAuthDetails implements AuthenticationDetailsSource<HttpServletRequest, com.sp.fc.web.config.RequestInfo> {


  @Override
  public RequestInfo buildDetails(HttpServletRequest request) {
    return RequestInfo.builder()
            .remoteIp(request.getRemoteAddr())
            .sessionId(request.getSession().getId())
            .loginTime()
  }
}
