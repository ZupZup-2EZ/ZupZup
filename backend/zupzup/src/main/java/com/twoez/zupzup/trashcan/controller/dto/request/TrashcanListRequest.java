package com.twoez.zupzup.trashcan.controller.dto.request;


import jakarta.validation.constraints.NotNull;
import java.math.BigDecimal;

public record TrashcanListRequest(
        @NotNull BigDecimal currentLatitude, // 위도
        @NotNull BigDecimal currentLongitude // 경도
        ) {}
