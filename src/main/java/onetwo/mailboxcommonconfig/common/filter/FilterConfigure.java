package onetwo.mailboxcommonconfig.common.filter;

import onetwo.mailboxcommonconfig.common.jwt.JwtTokenFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class FilterConfigure extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final JwtTokenFilter jwtTokenFilter;
    private final AccessKeyCheckFilter accessKeyCheckFilter;
    private final LoggingFilter loggingFilter;

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        if (jwtTokenFilter != null) builder.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
        if (accessKeyCheckFilter != null) builder.addFilterBefore(accessKeyCheckFilter, JwtTokenFilter.class);
        if (loggingFilter != null) builder.addFilterBefore(loggingFilter, AccessKeyCheckFilter.class);
    }
}
