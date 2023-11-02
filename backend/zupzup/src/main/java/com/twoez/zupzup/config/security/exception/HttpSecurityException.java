package com.twoez.zupzup.config.security.exception;


import com.twoez.zupzup.global.exception.ApplicationException;
import com.twoez.zupzup.global.exception.HttpExceptionCode;

public class HttpSecurityException extends ApplicationException {

    public HttpSecurityException(HttpExceptionCode exceptionCode) {
        super(exceptionCode);
    }
}
