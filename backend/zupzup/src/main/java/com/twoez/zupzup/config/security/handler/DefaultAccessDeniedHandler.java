package com.twoez.zupzup.config.security.handler;


import com.twoez.zupzup.config.security.HttpRequestEndpointChecker;
import com.twoez.zupzup.global.exception.HttpExceptionCode;
import com.twoez.zupzup.global.response.ErrorResponse;
import com.twoez.zupzup.global.util.Assertion;
import com.twoez.zupzup.global.util.ExceptionResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.stereotype.Component;

/** 인가에 대한 기본 예외 처리 핸들러 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DefaultAccessDeniedHandler extends AccessDeniedHandlerImpl {

    public static final String NOT_FOUND_SERVLET_MESSAGE = "해당 접근은 유효하지 않습니다.";

    private final HttpRequestEndpointChecker endpointChecker;

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException)
            throws IOException, ServletException {
        log.info("DefaultAccessDeniedHandler - handle called");
        HttpExceptionCode authorizationExceptionCode =
                HttpExceptionCode.SECURITY_AUTHORIZATION_EXCEPTION;

        Assertion.with(request)
                .setValidation(endpointChecker::existsEndPoint)
                .validateOrExecute(
                        () -> {
                            log.info(
                                    "[AccessDeniedHandler] {} {} 유효하지 않은 접근입니다.",
                                    request.getMethod(),
                                    request.getRequestURI());
                            try {
                                ExceptionResponseWriter.writeException(
                                        response,
                                        authorizationExceptionCode.getHttpStatus(),
                                        ErrorResponse.from(authorizationExceptionCode));
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                        });

        super.handle(request, response, accessDeniedException);
    }
}
