package com.onetwo.mailboxcommonconfig.common.jwt;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;

public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        HttpServletRequest requestToCache = new ContentCachingRequestWrapper(request);

        Exception exception = (Exception) requestToCache.getAttribute("exception");
        if (exception != null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, exception.getMessage());
        } else {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());
        }
    }
}
