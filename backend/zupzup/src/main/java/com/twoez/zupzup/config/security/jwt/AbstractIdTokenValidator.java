package com.twoez.zupzup.config.security.jwt;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.twoez.zupzup.config.security.dto.JwtHeader;
import com.twoez.zupzup.config.security.exception.InvalidIdTokenException;
import com.twoez.zupzup.config.security.exception.InvalidJwtException;
import com.twoez.zupzup.global.exception.HttpExceptionCode;
import com.twoez.zupzup.member.domain.AuthUser;
import com.twoez.zupzup.member.service.dto.OidcPublicKey;
import com.twoez.zupzup.member.service.dto.OidcPublicKeyList;
import java.util.Base64;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class AbstractIdTokenValidator {

    private final JwtValidator jwtValidator;
    private final OidcProperty oidcProperty;

    public AbstractIdTokenValidator(JwtValidator jwtValidator, OidcProperty oidcProperty) {
        this.jwtValidator = jwtValidator;
        this.oidcProperty = oidcProperty;
    }

    public AuthUser extractAuthUser(String idToken) {
        // idToken의 header로 부터 kid를 가져온다.
        String kid = extractKid(idToken);

        // kid로부터 oidcPublicKey를 받아온다.
        OidcPublicKey oidcPublicKey = getOidcPublicKeyByKid(kid);

        // publicKey로 payload를 얻어낸다.
        Map<String, Object> payload =
                jwtValidator.getPayloadFromIdToken(idToken, oidcPublicKey.n(), oidcPublicKey.e());

        // payload로부터 AuthUser를 얻어내서 반환한다.
        return extractUserInfo(payload);
    }

    private String extractKid(String idToken) {
        String headerToken = idToken.split("\\.")[0];
        byte[] decodedBytes = Base64.getDecoder().decode(headerToken);
        String header = new String(decodedBytes);

        ObjectMapper objectMapper = new ObjectMapper();
        try {
            JwtHeader jwtHeader = objectMapper.readValue(header, JwtHeader.class);
            log.info("kid : {}", jwtHeader.kid());
            return jwtHeader.kid();
        } catch (JsonProcessingException e) {
            throw new InvalidJwtException(HttpExceptionCode.JWT_UNSUPPORTED);
        }
    }

    /**
     * oauth provider의 공개키를 받아와(Http GET) kid에 일치하는 공개키를 반환합니다.
     *
     * @param kid
     * @return
     */
    private OidcPublicKey getOidcPublicKeyByKid(String kid) {
        OidcPublicKeyList publicKeys = getOidcPublicKeys();
        return publicKeys.keys().stream()
                .filter(key -> key.kid().equals(kid))
                .findFirst()
                .orElseThrow(
                        () -> new InvalidIdTokenException(HttpExceptionCode.ID_TOKEN_INVALID_KID));
    }

    public abstract OidcPublicKeyList getOidcPublicKeys();

    public abstract AuthUser extractUserInfo(Map<String, Object> payload);
}
