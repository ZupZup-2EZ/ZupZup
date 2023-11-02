package com.twoez.zupzup.config.security.exception;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class InvalidEnvironmentVariableException extends RuntimeException{
    public InvalidEnvironmentVariableException() {
        super("wrong value");
        log.error("wrong value");
    }
}
