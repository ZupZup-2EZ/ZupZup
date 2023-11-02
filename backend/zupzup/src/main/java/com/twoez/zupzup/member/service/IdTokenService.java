package com.twoez.zupzup.member.service;


import com.twoez.zupzup.config.security.jwt.IdTokenValidator;
import com.twoez.zupzup.config.security.jwt.JwtValidator;
import com.twoez.zupzup.member.controller.dto.AuthRequest;
import com.twoez.zupzup.member.domain.AuthUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class IdTokenService {

    private final JwtValidator jwtValidator;
    private final IdTokenValidator idTokenValidator;

    public AuthUser extractAuthUser(AuthRequest authRequest) {
        log.info("IdTokenService - extractAuthUser");

        // authRequest의 jwt에서 idToken을 가져온다. -> jwtValidator
        String idToken = jwtValidator.getIdTokenFromAuthToken(authRequest.authToken());

        // TODO : jwt에서 발생할 수 있는 에러에 대해 ControllerAdvice 처리를 한다.
        // IdTokenValidator로 idToken으로부터 AuthUser를 가져온다.
        return idTokenValidator.extractAuthUser(authRequest.oauthProvider(), idToken);
    }
}
