package com.twoez.zupzup.config.security.jwt;


import com.twoez.zupzup.config.security.exception.EmptyEnvironmentVariableException;
import com.twoez.zupzup.config.security.exception.InvalidEnvironmentVariableException;
import com.twoez.zupzup.config.security.exception.ShortEnvironmentVariableException;
import com.twoez.zupzup.config.security.exception.WrongEnvironmentVariableException;
import com.twoez.zupzup.global.util.Assertion;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
//@ConfigurationProperties("jwt")
public class JwtProperty {

    @Value("${jwt.secret-key}")
    private String secretKey;

    // TODO : Integer로 주입받는 방식 알아보기
    @Value("${jwt.auth-token-expired-second}")
    private String authTokenExpiredSecond;

    @Value("${jwt.access-expired-second}")
    private String accessExpiredSecond;

    @Value("${jwt.refresh-expired-second}")
    private String refreshExpiredSecond;

    @Bean
    public Key getKey() {
        return Keys.hmacShaKeyFor(Base64.encode(secretKey.getBytes()));
    }

    @Bean
    public Integer getAuthTokenExpiredSecond() {
        return Integer.parseInt(authTokenExpiredSecond);
    }

    @Bean
    public Integer getRefreshExpiredSecond() {
        return Integer.parseInt(refreshExpiredSecond);
    }

    @Bean
    public Integer getAccessExpiredSecond() {
        return Integer.parseInt(accessExpiredSecond);
    }
}
