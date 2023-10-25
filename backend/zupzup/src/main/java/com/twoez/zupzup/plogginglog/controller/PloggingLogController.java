package com.twoez.zupzup.plogginglog.controller;


import com.twoez.zupzup.global.response.ApiResponse;
import com.twoez.zupzup.plogginglog.controller.dto.response.PloggingLogListResponse;
import com.twoez.zupzup.plogginglog.controller.dto.response.RecentPloggingLogResponse;
import com.twoez.zupzup.plogginglog.service.PloggingLogQueryService;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/histories")
@RequiredArgsConstructor
public class PloggingLogController {

    private final PloggingLogQueryService ploggingLogQueryService;

    @GetMapping("/period")
    public ApiResponse<List<PloggingLogListResponse>> floggingListByPeriod(
            @RequestParam LocalDateTime startDate, @RequestParam LocalDateTime endDate) {
        return ApiResponse.ok(
                ploggingLogQueryService.searchInPeriod(startDate, endDate, 1L).stream()
                        .map(PloggingLogListResponse::from)
                        .toList());
    }

    @GetMapping("/days")
    public ApiResponse<List<PloggingLogListResponse>> floggingListByDay(
            @RequestParam LocalDate date) {
        return ApiResponse.ok(
                ploggingLogQueryService.searchByDate(date, 1L).stream()
                        .map(PloggingLogListResponse::from)
                        .toList());
    }

    @GetMapping("/recent")
    public ApiResponse<RecentPloggingLogResponse> recentFloggingLogDetails() {
        return ApiResponse.ok(
                RecentPloggingLogResponse.from(ploggingLogQueryService.searchRecentLog(1L)));
    }
}
