package com.twoez.zupzup.config.security.handler;


import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class Oauth2FailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception)
            throws IOException, ServletException {
        log.info("onAuthenticationFailure called");

        String errorMessage = "Authentication Fail";

        if (exception instanceof BadCredentialsException) {
            log.info("Bad Credential Exception");
            errorMessage = "Bad Credential";
        } else if (exception instanceof InsufficientAuthenticationException) {
            log.info("Insufficient Authentication Exception");
            errorMessage = "Invalid Secret Key";
        } else {
            log.info("other Authentication Exception");
            exception.printStackTrace();
        }
        setDefaultFailureUrl("/login?error=true&exception=" + errorMessage);
        super.onAuthenticationFailure(request, response, exception);
    }
}
