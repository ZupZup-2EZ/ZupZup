package com.twoez.zupzup.global.exception.common;


import com.twoez.zupzup.global.exception.ApplicationException;
import com.twoez.zupzup.global.exception.HttpExceptionCode;

public class InternalServerExceptions extends ApplicationException {
    public InternalServerExceptions() {
        super(HttpExceptionCode.INTERNAL_SERVER_EXCEPTION);
    }

    public InternalServerExceptions(String exceptionCode) {
        super(HttpExceptionCode.INTERNAL_SERVER_EXCEPTION, exceptionCode);
    }
}
