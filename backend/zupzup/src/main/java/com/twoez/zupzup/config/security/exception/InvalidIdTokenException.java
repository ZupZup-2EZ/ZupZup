package com.twoez.zupzup.config.security.exception;


import com.twoez.zupzup.global.exception.ApplicationException;
import com.twoez.zupzup.global.exception.HttpExceptionCode;

public class InvalidIdTokenException extends ApplicationException {

    public InvalidIdTokenException(HttpExceptionCode exceptionCode) {
        super(exceptionCode);
    }
}
