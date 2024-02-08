package com.onetwo.mailboxcommonconfig.common.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.http.MediaType;
import org.springframework.util.StreamUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;


@Slf4j
public class LoggingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        MDC.put("traceId", UUID.randomUUID().toString());

        if (isAsyncDispatch(request)) {
            filterChain.doFilter(request, response);
        } else {
            doFilterWrapped(new RequestWrapper(request), new ResponseWrapper(response), filterChain);
        }
        MDC.clear();
    }

    protected void doFilterWrapped(HttpServletRequest request, ContentCachingResponseWrapper response, FilterChain filterChain) throws ServletException, IOException {
        long start = System.currentTimeMillis();
        try {
            logRequest(request);
            filterChain.doFilter(request, response);
        } finally {
            long end = System.currentTimeMillis();
            long workTime = end - start;
            logResponse(response, workTime);
            response.copyBodyToResponse();
        }
    }

    private void logRequest(HttpServletRequest request) throws IOException {
        String queryString = request.getQueryString();
        log.info("Request : {} uri=[{}] request-ip=[{}] header=[{}] content-type=[{}] ",
                request.getMethod(),
                request.getRemoteAddr(),
                queryString == null ? request.getRequestURI() : request.getRequestURI() + "?" + queryString,
                getHeaders(request),
                request.getContentType()
        );

        logRequestPayload("Request", request.getContentType(), request.getInputStream());
    }

    private void logResponse(ContentCachingResponseWrapper response, long workTime) throws IOException {
        logResponsePayload("Response", response.getContentType(), response.getContentInputStream(), workTime);
    }

    private void logRequestPayload(String prefix, String contentType, InputStream inputStream) throws IOException {
        boolean visible = isVisible(MediaType.valueOf(contentType == null ? "application/json" : contentType));
        if (visible) {
            byte[] content = StreamUtils.copyToByteArray(inputStream);
            if (content.length > 0) {
                String contentString = new String(content);
                log.info("{} Payload: {}", prefix, contentString.replaceAll(System.getProperty("line.separator"), ""));
            }
        } else {
            log.info("{} Payload: Binary Content", prefix);
        }
    }

    private void logResponsePayload(String prefix, String contentType, InputStream inputStream, long workTime) throws IOException {
        boolean visible = isVisible(MediaType.valueOf(contentType == null ? "application/json" : contentType));
        if (visible) {
            byte[] content = StreamUtils.copyToByteArray(inputStream);
            if (content.length > 0) {
                String contentString = new String(content);
                log.info("{} Response Payload: {} ({}ms)", prefix, contentString, workTime);
            }
        } else {
            log.info("{} Response Payload: Binary Content ({}ms)", prefix, workTime);
        }
    }

    private static boolean isVisible(MediaType mediaType) {
        final List<MediaType> VISIBLE_TYPES = Arrays.asList(
                MediaType.valueOf("text/*"),
                MediaType.APPLICATION_FORM_URLENCODED,
                MediaType.APPLICATION_JSON,
                MediaType.APPLICATION_XML,
                MediaType.valueOf("application/*+json"),
                MediaType.valueOf("application/*+xml"),
                MediaType.MULTIPART_FORM_DATA
        );

        return VISIBLE_TYPES.stream()
                .anyMatch(visibleType -> visibleType.includes(mediaType));
    }


    private Map<String, Object> getHeaders(HttpServletRequest request) {
        Map<String, Object> headerMap = new HashMap<>();

        Enumeration<String> headerArray = request.getHeaderNames();
        while (headerArray.hasMoreElements()) {
            String headerName = headerArray.nextElement();
            headerMap.put(headerName, request.getHeader(headerName));
        }
        return headerMap;
    }
}
