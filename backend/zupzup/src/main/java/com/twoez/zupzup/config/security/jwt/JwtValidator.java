package com.twoez.zupzup.config.security.jwt;


import com.twoez.zupzup.config.security.exception.InvalidAuthorizationTokenException;
import com.twoez.zupzup.config.security.exception.InvalidIdTokenException;
import com.twoez.zupzup.global.exception.HttpExceptionCode;
import com.twoez.zupzup.global.util.Assertion;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JwtValidator {
    private final Key secretKey;

    public JwtValidator(JwtProperty jwtProperty) {
        this.secretKey = jwtProperty.getKey();
    }

    public Claims getTokenClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String getIdTokenFromAuthToken(String authToken) {
        Jws<Claims> validatedClaims = validateAuthorizationToken(authToken);

        Object idToken = validatedClaims.getBody().get("idToken");
        Assertion.with(idToken)
                .setValidation(Objects::nonNull)
                .validateOrThrow(
                        () ->
                                new InvalidIdTokenException(
                                        HttpExceptionCode.ID_TOKEN_KID_NOT_FOUND));

        return (String) idToken;
    }

    private Jws<Claims> validateAuthorizationToken(String authorizationToken) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(authorizationToken);
        } catch (ExpiredJwtException e) {
            throw new InvalidAuthorizationTokenException(HttpExceptionCode.JWT_EXPIRED);
        } catch (MalformedJwtException e) {
            throw new InvalidAuthorizationTokenException(HttpExceptionCode.JWT_MALFORMED);
        } catch (UnsupportedJwtException e) {
            throw new InvalidIdTokenException(HttpExceptionCode.JWT_UNSUPPORTED);
        } catch (Exception e) {
            log.warn("처리되지 않은 Exception 발생");
            e.printStackTrace();
            throw new InvalidIdTokenException(HttpExceptionCode.JWT_NOT_FOUND);
        }
    }

    public Map<String, Object> getPayloadFromIdToken(
            String idToken, String modulus, String exponent) {
        Jws<Claims> claimsJws = validateSignatureIdToken(idToken, modulus, exponent);
        return claimsJws.getBody();
    }

    private Jws<Claims> validateSignatureIdToken(String idToken, String modulus, String exponent) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getRsaPublicKey(modulus, exponent))
                    .build()
                    .parseClaimsJws(idToken);
        } catch (ExpiredJwtException e) {
            throw new InvalidAuthorizationTokenException(HttpExceptionCode.JWT_EXPIRED);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new InvalidIdTokenException(HttpExceptionCode.ID_TOKEN_INVALID_SIGNATURE);
        } catch (Exception e) {
            log.warn("처리되지 않은 Exception 발생 - validateSignatureIdToken");
            e.printStackTrace();
            throw new InvalidIdTokenException(HttpExceptionCode.JWT_NOT_FOUND);
        }
    }

    private Key getRsaPublicKey(String modulus, String exponent)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedModulus = Base64.getUrlDecoder().decode(modulus);
        byte[] decodeExponent = Base64.getUrlDecoder().decode(exponent);

        BigInteger mod = new BigInteger(1, decodedModulus);
        BigInteger exp = new BigInteger(1, decodeExponent);
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
        return keyFactory.generatePublic(keySpec);
    }

    public Long getMemberIdFromAccessToken(String accessToken) {
        Jws<Claims> validatedClaims = validateAuthorizationToken(accessToken);
        String memberId = validatedClaims.getBody().getSubject();
        Assertion.with(memberId)
                .setValidation(Objects::nonNull)
                .validateOrThrow(
                        () ->
                                new InvalidAuthorizationTokenException(
                                        HttpExceptionCode.MEMBER_ID_NOT_FOUND_IN_ACCESS_TOKEN));

        return Long.valueOf(memberId);
    }
}
