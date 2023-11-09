package com.twoez.zupzup.config.security.jwt;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

/**
 * 인증 완료 후 유저에 대한 token을 발급해주는 Provider
 */
@Component
public class Oauth2JwtProvider extends AbstractJwtProvider {

    public Oauth2JwtProvider(JwtProperty jwtProperty) {
        super(jwtProperty);
    }

    @Override
    public String createAuthToken(OAuth2User oAuth2User) {
        Claims claims = Jwts.claims();
        claims.put("id", oAuth2User.getName());
        return generateToken(oAuth2User, claims, authTokenExpiredSecond);
    }

    @Override
    protected String generateToken(OAuth2User oAuth2User, Claims claims, Integer validationSecond) {
        Instant expiredTime = Instant.now().plus(validationSecond, ChronoUnit.SECONDS);
        return Jwts.builder()
                .setSubject(oAuth2User.getName())
                .setClaims(claims)
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .setExpiration(Date.from(expiredTime))
                .compact();
    }
}
