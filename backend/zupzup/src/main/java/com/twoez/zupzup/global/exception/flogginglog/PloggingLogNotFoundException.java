package com.twoez.zupzup.global.exception.flogginglog;


import com.twoez.zupzup.global.exception.ApplicationException;
import com.twoez.zupzup.global.exception.ExceptionCode;
import lombok.Getter;

@Getter
public class PloggingLogNotFoundException extends ApplicationException {

    public PloggingLogNotFoundException(ExceptionCode exceptionCode) {
        super(exceptionCode);
    }

    public PloggingLogNotFoundException() {
        this(ExceptionCode.PLOGGING_LOG_NOT_FOUND);
    }
}
