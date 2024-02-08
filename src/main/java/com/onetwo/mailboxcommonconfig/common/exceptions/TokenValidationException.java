package com.onetwo.mailboxcommonconfig.common.exceptions;

import com.onetwo.mailboxcommonconfig.common.jwt.JwtCode;
import lombok.Getter;

@Getter
public class TokenValidationException extends RuntimeException {

    public TokenValidationException(JwtCode code) {
        super(code.getValue());
    }
}
