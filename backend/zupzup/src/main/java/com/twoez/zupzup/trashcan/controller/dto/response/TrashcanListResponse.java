package com.twoez.zupzup.trashcan.controller.dto.response;


import com.twoez.zupzup.trashcan.domain.Trashcan;
import java.math.BigDecimal;
import lombok.Builder;

@Builder
public record TrashcanListResponse(
        BigDecimal latitude, // 위도
        BigDecimal longitude, // 경도
        String trashcanType) {
    public static TrashcanListResponse from(Trashcan trashcan) {
        return TrashcanListResponse.builder()
                .latitude(trashcan.getLatitude())
                .longitude(trashcan.getLongitude())
                .trashcanType(trashcan.getTrashcanType())
                .build();
    }
}
