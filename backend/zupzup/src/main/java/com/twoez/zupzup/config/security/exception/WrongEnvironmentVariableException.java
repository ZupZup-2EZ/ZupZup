package com.twoez.zupzup.config.security.exception;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class WrongEnvironmentVariableException extends RuntimeException {

    public WrongEnvironmentVariableException() {
        super("definitely wrong env");
        log.error("definitely wrong env");
    }

}
