package com.onetwo.mailboxcommonconfig.common.jwt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum JwtCode {

    ACCESS_TOKEN_ACCESSED("access-token-accessed"),
    ACCESS_TOKEN_EXPIRED("access-token-expired"),
    ACCESS_TOKEN_DENIED("access-token-denied"),
    REFRESH_TOKEN_ACCESSED("refresh-token-accessed"),
    REFRESH_TOKEN_EXPIRED("refresh-token-expired"),
    REFRESH_TOKEN_DENIED("refresh-token-denied");

    private final String value;
}
