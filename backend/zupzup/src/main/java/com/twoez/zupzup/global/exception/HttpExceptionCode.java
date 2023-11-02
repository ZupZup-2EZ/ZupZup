package com.twoez.zupzup.global.exception;


import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum HttpExceptionCode {
    UNEXPECTED_EXCEPTION(HttpStatus.INTERNAL_SERVER_ERROR, "ERR_GLOBAL_001", "예상치 못한 오류가 발생했습니다."),
    INTERNAL_SERVER_EXCEPTION(
            HttpStatus.INTERNAL_SERVER_ERROR, "ERR_GLOBAL_999", "서버 내부에서 오류가 발생했습니다."),

    SECURITY_AUTHORIZATION_EXCEPTION(HttpStatus.FORBIDDEN, "ERR_AUTH_001", "사용자 인가에 실패했습니다."),
    SECURITY_AUTHENTICATION_EXCEPTION(HttpStatus.FORBIDDEN, "ERR_AUTH_002", "사용자 인증에 실패했습니다."),
    INVALID_AUTHORIZATION_HEADER(
            HttpStatus.UNAUTHORIZED, "ERR_AUTH_003", "Authorization Header가 유효하지 않습니다."),
    MEMBER_ID_NOT_FOUND_IN_ACCESS_TOKEN(
            HttpStatus.UNAUTHORIZED, "ERR_AUTH_004", "memberId가 Token에 존재하지 않습니다."),

    OAUTH_PROVIDER_NOT_FOUND(
            HttpStatus.BAD_REQUEST, "ERR_OAUTH_001", "Oauth Provider 가 존재하지 않습니다."),
    OAUTH_PROVIDER_NULL_EXCEPTION(
            HttpStatus.BAD_REQUEST, "ERR_OAUTH_002", "Oauth Provider Value는 null이 될 수 없습니다."),

    JWT_EXPIRED(HttpStatus.UNAUTHORIZED, "ERR_JWT_001", "JWT 기한이 만료되었습니다."),
    JWT_MALFORMED(HttpStatus.UNAUTHORIZED, "ERR_JWT_002", "JWT가 손상되었습니다."),
    JWT_UNSUPPORTED(HttpStatus.UNAUTHORIZED, "ERR_JWT_003", "지원되지 않는 JWT 입니다."),
    JWT_INVALID_SIGNATURE(HttpStatus.UNAUTHORIZED, "ERR_JWT_004", "signature가 유효하지 않습니다."),
    JWT_NOT_FOUND(HttpStatus.UNAUTHORIZED, "ERR_JWT_005", "JWT를 찾을 수 없습니다."),
    ID_TOKEN_NOT_FOUND(HttpStatus.NOT_FOUND, "ERR_JWT_006", "authToken에서 idToken을 찾을 수 없습니다."),

    ID_TOKEN_KID_NOT_FOUND(
            HttpStatus.UNAUTHORIZED, "ERR_IDTOKEN_001", "유효한 Id Token이 아닙니다. - kid가 존재하지 않습니다."),
    ID_TOKEN_INVALID_KID(
            HttpStatus.UNAUTHORIZED,
            "ERR_IDTOKEN_002",
            "유효한 Id Token이 아닙니다. - 출처를 알 수 없는 token입니다."),
    ID_TOKEN_INVALID_SIGNATURE(
            HttpStatus.UNAUTHORIZED, "ERR_IDTOKEN_003", "유효한 Id Token이 아닙니다. - 유효한 서명이 아닙니다."),

    OIDC_PUBLIC_KEY_FEIGN_FAIL(
            HttpStatus.INTERNAL_SERVER_ERROR, "ERR_OIDC_001", "Oidc 공개키 목록을 가져오는데 실패하였습니다."),

    MEMBER_NOT_FOUND(HttpStatus.BAD_REQUEST, "ERR_MEMBER_001", "요청된 멤버를 찾을 수 없습니다."),

    PLOGGING_LOG_NOT_FOUND(HttpStatus.NOT_FOUND, "ERR_PLOGGING_LOG_001", "플로깅 기록을 찾을 수 없습니다."),

    ROUTE_NOT_FOUND(HttpStatus.NOT_FOUND, "ERR_PLOGGING_LOG_002", "플로깅 이동경로를 찾을 수 없습니다.");

    private final HttpStatus httpStatus;
    private final String errorCode;
    private final String message;
}
