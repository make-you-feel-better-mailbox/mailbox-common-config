package onetwo.mailboxcommonconfig.common.exceptions;

import onetwo.mailboxcommonconfig.common.jwt.JwtCode;
import lombok.Getter;

@Getter
public class TokenValidationException extends RuntimeException {

    public TokenValidationException(JwtCode code) {
        super(code.getValue());
    }
}
