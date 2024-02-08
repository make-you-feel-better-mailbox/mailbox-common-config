package onetwo.mailboxcommonconfig.common;

import onetwo.mailboxcommonconfig.common.filter.AccessKeyCheckFilter;
import onetwo.mailboxcommonconfig.common.filter.FilterConfigure;
import onetwo.mailboxcommonconfig.common.filter.LoggingFilter;
import onetwo.mailboxcommonconfig.common.jwt.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@AutoConfiguration
@EnableWebSecurity
@ConditionalOnProperty(name = "mailbox-auto-config.option", havingValue = "on")
public class MailBoxCommonAutoConfig {

    private static final String MAILBOX_AUTO_CONFIG_PROPERTY = "mailbox-auto-config";
    private static final String ACCESS_KEY_CHECK_PROPERTY = MAILBOX_AUTO_CONFIG_PROPERTY + ".access-key-check";
    private static final String LOGGING_PROPERTY = MAILBOX_AUTO_CONFIG_PROPERTY + ".logging";
    private static final String SECURITY_PROPERTY = MAILBOX_AUTO_CONFIG_PROPERTY + ".security";

    @Bean
    @ConditionalOnProperty(name = ACCESS_KEY_CHECK_PROPERTY, havingValue = GlobalStatus.HAVING_VALUE_TRUE)
    public AccessKeyCheckFilter accessKeyCheckFilter() {
        return new AccessKeyCheckFilter();
    }

    @Bean
    @ConditionalOnProperty(name = LOGGING_PROPERTY, havingValue = GlobalStatus.HAVING_VALUE_ON)
    public LoggingFilter loggingFilter() {
        return new LoggingFilter();
    }

    @Bean
    @ConditionalOnProperty(name = SECURITY_PROPERTY, havingValue = GlobalStatus.HAVING_VALUE_ON)
    public JwtTokenFilter jwtTokenFilter(TokenProvider tokenProvider) {
        return new JwtTokenFilter(tokenProvider);
    }

    @Bean
    @ConditionalOnProperty(name = SECURITY_PROPERTY, havingValue = GlobalStatus.HAVING_VALUE_ON)
    public JwtAccessDeniedHandler jwtAccessDeniedHandler() {
        return new JwtAccessDeniedHandler();
    }

    @Bean
    @ConditionalOnProperty(name = SECURITY_PROPERTY, havingValue = GlobalStatus.HAVING_VALUE_ON)
    public JwtTokenProvider jwtTokenProvider(@Value("${jwt.secret-key}") String secretKey) {
        return new JwtTokenProvider(secretKey);
    }

    @Bean
    public FilterConfigure filterConfigure(TokenProvider tokenProvider) {
        return new FilterConfigure(jwtTokenFilter(tokenProvider), accessKeyCheckFilter(), loggingFilter());
    }

    @Bean
    @ConditionalOnProperty(name = SECURITY_PROPERTY, havingValue = GlobalStatus.HAVING_VALUE_ON)
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }

    /*
     * Security config
     */
    private static final String[] WHITE_LIST = {
            "/favicon.ico", "/docs/**"
    };

    @Bean
    @ConditionalOnProperty(name = SECURITY_PROPERTY, havingValue = GlobalStatus.HAVING_VALUE_ON)
    public MvcRequestMatcher.Builder mvcRequestMatcherBuilder(HandlerMappingIntrospector introspect) {
        return new MvcRequestMatcher.Builder(introspect);
    }

    @Bean
    @ConditionalOnProperty(name = SECURITY_PROPERTY, havingValue = GlobalStatus.HAVING_VALUE_ON)
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity, TokenProvider tokenProvider, MvcRequestMatcher.Builder mvc, RequestMatcher requestMatcher) throws Exception {
        List<MvcRequestMatcher> requestMatchers = Stream.of(WHITE_LIST).map(mvc::pattern).collect(Collectors.toList());

        if (requestMatcher != null) requestMatchers.addAll(requestMatcher.getMvcRequestMatcherArray());

        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .headers(headers ->
                        headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)
                )
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .exceptionHandling(exceptionHandling ->
                        exceptionHandling.authenticationEntryPoint(jwtAuthenticationEntryPoint())
                                .accessDeniedHandler(jwtAccessDeniedHandler())
                )
                .authorizeHttpRequests(authorizeHttpRequests ->
                        authorizeHttpRequests
                                .requestMatchers(PathRequest.toH2Console()).permitAll()
                                .requestMatchers(requestMatchers.toArray(MvcRequestMatcher[]::new)).permitAll()
                                .anyRequest().authenticated()
                )
                .apply(filterConfigure(tokenProvider));

        return httpSecurity.build();
    }
}
