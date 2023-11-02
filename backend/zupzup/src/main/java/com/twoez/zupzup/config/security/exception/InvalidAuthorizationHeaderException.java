package com.twoez.zupzup.config.security.exception;


import com.twoez.zupzup.global.exception.ApplicationException;
import com.twoez.zupzup.global.exception.HttpExceptionCode;

public class InvalidAuthorizationHeaderException extends ApplicationException {

    public InvalidAuthorizationHeaderException() {
        super(HttpExceptionCode.INVALID_AUTHORIZATION_HEADER);
    }
}
