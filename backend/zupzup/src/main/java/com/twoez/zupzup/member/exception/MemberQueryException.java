package com.twoez.zupzup.member.exception;


import com.twoez.zupzup.global.exception.ApplicationException;
import com.twoez.zupzup.global.exception.HttpExceptionCode;

public class MemberQueryException extends ApplicationException {
    public MemberQueryException(HttpExceptionCode exceptionCode) {
        super(exceptionCode);
    }
}
