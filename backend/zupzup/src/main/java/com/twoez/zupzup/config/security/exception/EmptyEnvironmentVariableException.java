package com.twoez.zupzup.config.security.exception;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class EmptyEnvironmentVariableException extends RuntimeException {

    public EmptyEnvironmentVariableException() {
        super("empty value");
        log.error("empty value");
    }

}
