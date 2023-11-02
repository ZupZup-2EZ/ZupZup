package com.twoez.zupzup.config.security.jwt;


import lombok.Getter;

@Getter
public class AuthorizationToken {

    private String accessToken;
    private String refreshToken;
    private String grantType;

    public AuthorizationToken(String accessToken, String refreshToken, String grantType) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.grantType = grantType;
    }
}
