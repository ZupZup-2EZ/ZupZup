package com.twoez.zupzup.config.security.jwt;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;
import java.security.Key;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

/** 인증 완료 후 유저에 대한 token을 발급해주는 Provider */
public abstract class AbstractJwtProvider {

    protected static final String GRANT_TYPE = "Bearer";

    protected final Key secretKey;
    protected final Integer authTokenExpiredSecond;
    protected final Integer accessExpiredSecond;
    protected final Integer refreshExpiredSecond;

    protected AbstractJwtProvider(JwtProperty jwtProperty) {
        this.secretKey = jwtProperty.getKey();
        this.authTokenExpiredSecond = jwtProperty.getAuthTokenExpiredSecond();
        this.accessExpiredSecond = jwtProperty.getAccessExpiredSecond();
        this.refreshExpiredSecond = jwtProperty.getRefreshExpiredSecond();
    }

    public abstract String createAuthToken(OAuth2User oAuth2User);

    protected abstract String generateToken(OAuth2User oAuth2User, Claims claims, Integer validationSecond);

    public AuthorizationToken createAuthorizationToken(Long memberId) {
        String accessToken = generateToken(memberId, accessExpiredSecond);
        String refreshToken = generateToken(memberId, refreshExpiredSecond);
        return new AuthorizationToken(accessToken, refreshToken, GRANT_TYPE);
    }

    // TODO : 토큰의 종류를 구분할 수 있도록 수정하기
    private String generateToken(Long memberId, Integer validationSecond) {
        Instant expiredTime = Instant.now().plus(validationSecond, ChronoUnit.SECONDS);
        return Jwts.builder()
                .setSubject(String.valueOf(memberId))
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .setExpiration(Date.from(expiredTime))
                .compact();
    }
}
