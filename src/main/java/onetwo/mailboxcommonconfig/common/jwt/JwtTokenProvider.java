package onetwo.mailboxcommonconfig.common.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import onetwo.mailboxcommonconfig.common.domain.RoleNames;
import onetwo.mailboxcommonconfig.common.exceptions.TokenValidationException;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.security.Key;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

@Slf4j
public class JwtTokenProvider implements TokenProvider {

    private final String secretKey;
    private final Environment environment;

    public JwtTokenProvider(Environment environment) {
        this.environment = environment;
        this.secretKey = environment.getProperty("jwt.secret-key");
    }

    private Key key;

    @PostConstruct
    public void init() throws Exception {
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
        key = Keys.hmacShaKeyFor(encodedKey.getBytes());
    }

    @Override
    public Authentication getAuthentication(String token) {
        Claims claims = getClaimsByToken(token);
        String userId = claims.getSubject();

        Set<GrantedAuthority> authorities = getGrantedAuthoritiesByUserId(userId);

        return new UsernamePasswordAuthenticationToken(userId, token, authorities);
    }

    private Set<GrantedAuthority> getGrantedAuthoritiesByUserId(String userId) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority(RoleNames.ROLE_USER.getValue()));
        return authorities;
    }

    @Override
    public Claims getClaimsByToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // 토큰 유효성 검사
    @Override
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            throw new TokenValidationException(JwtCode.ACCESS_TOKEN_EXPIRED);
        } catch (JwtException | IllegalArgumentException e) {
            log.info("JwtException Token Denied : {}", e.getMessage());
            throw new TokenValidationException(JwtCode.ACCESS_TOKEN_DENIED);
        }
    }
}