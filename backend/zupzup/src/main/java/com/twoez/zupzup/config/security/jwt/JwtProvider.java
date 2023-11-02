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
import org.springframework.stereotype.Component;

/** 인증 완료 후 유저에 대한 token을 발급해주는 Provider */
@Component
public class JwtProvider {

    private static final String GRANT_TYPE = "Bearer";

    private final Key secretKey;
    private final Integer authTokenExpiredSecond;
    private final Integer accessExpiredSecond;
    private final Integer refreshExpiredSecond;

    public JwtProvider(JwtProperty jwtProperty) {
        this.secretKey = jwtProperty.getKey();
        this.authTokenExpiredSecond = jwtProperty.getAuthTokenExpiredSecond();
        this.accessExpiredSecond = jwtProperty.getAccessExpiredSecond();
        this.refreshExpiredSecond = jwtProperty.getRefreshExpiredSecond();
    }

    /**
     * IdToken을 담은 Jwt 생성
     *
     * @return
     */
    public String createAuthToken(OidcUser oidcUser) {
        Map<String, Object> idTokenAttribute = new HashMap<>();
        idTokenAttribute.put("idToken", oidcUser.getIdToken().getTokenValue());
        Claims claims = new DefaultClaims(idTokenAttribute);
        return generateToken(oidcUser, claims, authTokenExpiredSecond);
    }

    public AuthorizationToken createAuthorizationToken(Long memberId) {
        String accessToken = generateToken(memberId, accessExpiredSecond);
        String refreshToken = generateToken(memberId, refreshExpiredSecond);
        return new AuthorizationToken(accessToken, refreshToken, GRANT_TYPE);
    }

    private String generateToken(Long memberId, Integer validationSecond) {
        Instant expiredTime = Instant.now().plus(validationSecond, ChronoUnit.SECONDS);
        return Jwts.builder()
                .setSubject(String.valueOf(memberId))
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .setExpiration(Date.from(expiredTime))
                .compact();
    }

    private String generateToken(OidcUser oidcUser, Claims claims, Integer validationSecond) {
        Instant expiredTime = Instant.now().plus(validationSecond, ChronoUnit.SECONDS);
        return Jwts.builder()
                .setSubject(oidcUser.getSubject())
                .setClaims(claims)
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .setExpiration(Date.from(expiredTime))
                .compact();
    }
}
