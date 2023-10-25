package com.twoez.zupzup.plogginglog.controller.dto.response;


import com.twoez.zupzup.plogginglog.domain.PloggingLog;
import java.time.LocalDateTime;
import lombok.Builder;

@Builder
public record RecentPloggingLogResponse(
        LocalDateTime startDateTime,
        LocalDateTime endDateTime,
        Integer distance,
        Integer calories) {

    public static RecentPloggingLogResponse from(PloggingLog ploggingLog) {
        return RecentPloggingLogResponse.builder()
                .startDateTime(ploggingLog.getStartDateTime())
                .endDateTime(ploggingLog.getEndDateTime())
                .distance(ploggingLog.getDistance())
                .calories(ploggingLog.getCalories())
                .build();
    }
}
