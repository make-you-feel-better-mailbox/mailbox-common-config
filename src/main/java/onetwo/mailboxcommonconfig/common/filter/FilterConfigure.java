package onetwo.mailboxcommonconfig.common.filter;

import lombok.RequiredArgsConstructor;
import onetwo.mailboxcommonconfig.common.jwt.JwtTokenFilter;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import java.util.Optional;

@RequiredArgsConstructor
public class FilterConfigure extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final JwtTokenFilter jwtTokenFilter;
    private final Optional<AccessKeyCheckFilter> accessKeyCheckFilterOpt;
    private final LoggingFilter loggingFilter;

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        if (jwtTokenFilter != null) builder.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
        if (accessKeyCheckFilterOpt.isPresent()) {
            if (jwtTokenFilter == null)
                builder.addFilterBefore(accessKeyCheckFilterOpt.get(), UsernamePasswordAuthenticationFilter.class);
            else builder.addFilterBefore(accessKeyCheckFilterOpt.get(), JwtTokenFilter.class);
        }
        if (loggingFilter != null) builder.addFilterBefore(loggingFilter, LogoutFilter.class);
    }
}
