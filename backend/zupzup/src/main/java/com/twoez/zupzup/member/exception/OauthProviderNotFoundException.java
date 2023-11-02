package com.twoez.zupzup.member.exception;


import com.twoez.zupzup.global.exception.ApplicationException;
import com.twoez.zupzup.global.exception.HttpExceptionCode;

public class OauthProviderNotFoundException extends ApplicationException {

    public OauthProviderNotFoundException() {
        super(HttpExceptionCode.OAUTH_PROVIDER_NOT_FOUND);
    }
}
