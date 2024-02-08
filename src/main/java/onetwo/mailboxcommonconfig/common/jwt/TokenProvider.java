package onetwo.mailboxcommonconfig.common.jwt;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;

public interface TokenProvider {

    Authentication getAuthentication(String token);

    Claims getClaimsByToken(String token);

    boolean validateToken(String token);
}
