package com.twoez.zupzup.config.security.handler;

import com.twoez.zupzup.config.security.HttpRequestEndpointChecker;
import com.twoez.zupzup.global.exception.HttpExceptionCode;
import com.twoez.zupzup.global.response.ErrorResponse;
import com.twoez.zupzup.global.util.Assertion;
import com.twoez.zupzup.global.util.ExceptionResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.stereotype.Component;

/**
 * 인증에 대한 기본 예외 처리 핸들러
 */

@Slf4j
@Component
@RequiredArgsConstructor
public class DefaultAuthenticationEntryPoint extends Http403ForbiddenEntryPoint {

    private final HttpRequestEndpointChecker endpointChecker;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException arg2) throws IOException {
        log.info("DefaultAuthenticationEntryPoint - commence called");
        log.info("request : {}", request);
        log.info("response: {}", response);
        arg2.printStackTrace();
        HttpExceptionCode authenticationExceptionCode = HttpExceptionCode.SECURITY_AUTHENTICATION_EXCEPTION;

        Assertion.with(request)
                .setValidation(endpointChecker::existsEndPoint)
                .validateOrExecute(() -> {
                    log.info("[AuthenticationEntryPoint] {} {} 유효하지 않은 접근입니다.", request.getMethod(),
                            request.getRequestURI());
                    try {
                        ExceptionResponseWriter.writeException(
                                response,
                                authenticationExceptionCode.getHttpStatus(),
                                ErrorResponse.from(authenticationExceptionCode)
                        );
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
        log.info("msg : {}", arg2.getMessage());
        log.info("Cause : {}", arg2.getCause());
        StackTraceElement[] stackTrace = arg2.getStackTrace();
        log.info("StackTrace");
        for (StackTraceElement st : stackTrace) {
            log.info("stack : {}", st);
        }

        super.commence(request, response, arg2);
    }
}
