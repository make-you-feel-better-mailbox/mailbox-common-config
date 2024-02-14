package onetwo.mailboxcommonconfig.common.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import onetwo.mailboxcommonconfig.common.GlobalStatus;
import onetwo.mailboxcommonconfig.common.exceptions.BadRequestException;
import org.springframework.core.env.Environment;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class AccessKeyCheckFilter extends OncePerRequestFilter {

    private final Environment environment;

    private String accessId;

    private String accessKey;

    public AccessKeyCheckFilter(Environment environment) {
        this.environment = environment;
        this.accessId = environment.getProperty(GlobalStatus.ACCESS_ID);
        this.accessKey = environment.getProperty(GlobalStatus.ACCESS_KEY);
    }

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String requestAccessId = request.getHeader(GlobalStatus.ACCESS_ID);
        String requestAccessKey = request.getHeader(GlobalStatus.ACCESS_KEY);

        if (!accessId.equals(requestAccessId) || !accessKey.equals(requestAccessKey))
            throw new BadRequestException("access-id or access-key does not matches");

        log.info("Server Access-id and Access-Key check passed");

        filterChain.doFilter(request, response);
    }
}
