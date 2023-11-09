package com.twoez.zupzup.config.security.jwt;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

/**
 * 인증 완료 후 유저에 대한 token을 발급해주는 Provider
 */
@Component
public class OidcJwtProvider extends AbstractJwtProvider {

    public OidcJwtProvider(JwtProperty jwtProperty) {
        super(jwtProperty);
    }

    /**
     * IdToken을 담은 Jwt 생성
     *
     * @return
     */
    @Override
    public String createAuthToken(OAuth2User oAuth2User) {
        OidcUser oidcUser = (OidcUser) oAuth2User;
        Map<String, Object> idTokenAttribute = new HashMap<>();
        idTokenAttribute.put("idToken", oidcUser.getIdToken().getTokenValue());
        Claims claims = new DefaultClaims(idTokenAttribute);
        return generateToken(oidcUser, claims, authTokenExpiredSecond);
    }

    @Override
    protected String generateToken(OAuth2User oAuth2User, Claims claims, Integer validationSecond) {
        OidcUser oidcUser = (OidcUser) oAuth2User;
        Instant expiredTime = Instant.now().plus(validationSecond, ChronoUnit.SECONDS);
        return Jwts.builder()
                .setSubject(oidcUser.getSubject())
                .setClaims(claims)
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .setExpiration(Date.from(expiredTime))
                .compact();
    }
}
