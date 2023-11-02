package com.twoez.zupzup.plogging.controller.dto;


import com.twoez.zupzup.plogging.domain.Plogger;

public record PloggerResponse(Long totalPlogger) {

    public static PloggerResponse from(Plogger plogger) {

        return new PloggerResponse(plogger.getTotal());
    }
}
