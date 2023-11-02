package com.twoez.zupzup.config.security.exception;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ShortEnvironmentVariableException extends RuntimeException {
    public ShortEnvironmentVariableException() {
        super("Short wrong env");
        log.error("Short wrong env");
    }
}
