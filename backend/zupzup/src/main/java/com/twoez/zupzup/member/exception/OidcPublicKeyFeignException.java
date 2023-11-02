package com.twoez.zupzup.member.exception;


import com.twoez.zupzup.global.exception.ApplicationException;
import com.twoez.zupzup.global.exception.HttpExceptionCode;

public class OidcPublicKeyFeignException extends ApplicationException {

    public OidcPublicKeyFeignException() {
        super(HttpExceptionCode.OIDC_PUBLIC_KEY_FEIGN_FAIL);
    }
}
