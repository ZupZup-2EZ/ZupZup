package com.twoez.zupzup.config.security.exception;


import com.twoez.zupzup.global.exception.ApplicationException;
import com.twoez.zupzup.global.exception.HttpExceptionCode;

public class InvalidJwtException extends ApplicationException {

    public InvalidJwtException(HttpExceptionCode exceptionCode) {
        super(exceptionCode);
    }
}
