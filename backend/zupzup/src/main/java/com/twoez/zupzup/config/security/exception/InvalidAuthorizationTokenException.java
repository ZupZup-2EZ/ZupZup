package com.twoez.zupzup.config.security.exception;


import com.twoez.zupzup.global.exception.ApplicationException;
import com.twoez.zupzup.global.exception.HttpExceptionCode;

public class InvalidAuthorizationTokenException extends ApplicationException {

    public InvalidAuthorizationTokenException(HttpExceptionCode exceptionCode) {
        super(exceptionCode);
    }
}
