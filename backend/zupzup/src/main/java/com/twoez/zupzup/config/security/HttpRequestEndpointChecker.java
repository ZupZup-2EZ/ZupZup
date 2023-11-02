package com.twoez.zupzup.config.security;


import com.twoez.zupzup.global.util.Assertion;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.HandlerMapping;

/** 요청된 api url을 처리하는 컨트롤러가 있는지 확인합니다. */
@Component
@RequiredArgsConstructor
public class HttpRequestEndpointChecker {

    private final DispatcherServlet dispatcherServlet;

    public boolean existsEndPoint(HttpServletRequest request) {
        List<HandlerMapping> handlerMappings = dispatcherServlet.getHandlerMappings();
        Assertion.with(handlerMappings)
                .setValidation(Objects::nonNull)
                .validateOrThrow(() -> new IllegalStateException("Invoked prior to onRefresh"));

        assert dispatcherServlet.getHandlerMappings() != null;
        try {
            for (HandlerMapping handlerMapping : dispatcherServlet.getHandlerMappings()) {
                HandlerExecutionChain handler = handlerMapping.getHandler(request);
                if (Objects.nonNull(handler)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
