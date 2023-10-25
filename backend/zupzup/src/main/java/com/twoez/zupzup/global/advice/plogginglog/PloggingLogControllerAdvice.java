package com.twoez.zupzup.global.advice.plogginglog;

import com.twoez.zupzup.global.advice.AdviceLoggingUtils;
import com.twoez.zupzup.global.exception.flogginglog.PloggingLogNotFoundException;
import com.twoez.zupzup.global.response.ApiResponse;
import com.twoez.zupzup.global.response.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class PloggingLogControllerAdvice {

    @ExceptionHandler(PloggingLogNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ApiResponse<ErrorResponse> ploggingLogNotFound(PloggingLogNotFoundException e) {
        AdviceLoggingUtils.exceptionLog(e);
        return ApiResponse.notFound(ErrorResponse.from(e.getExceptionCode()));
    }
}
