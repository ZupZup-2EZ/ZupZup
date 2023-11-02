package com.twoez.zupzup.member.exception;


import com.twoez.zupzup.global.exception.ApplicationException;
import com.twoez.zupzup.global.exception.HttpExceptionCode;

public class OauthProviderConvertException extends ApplicationException {

    public OauthProviderConvertException(HttpExceptionCode exceptionCode) {
        super(exceptionCode);
    }
}
