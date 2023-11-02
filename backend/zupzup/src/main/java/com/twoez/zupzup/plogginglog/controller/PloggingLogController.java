package com.twoez.zupzup.plogginglog.controller;


import com.twoez.zupzup.global.response.ApiResponse;
import com.twoez.zupzup.member.domain.LoginUser;
import com.twoez.zupzup.plogginglog.controller.dto.request.PloggingLogRequest;
import com.twoez.zupzup.plogginglog.controller.dto.response.PloggingLogAddResponse;
import com.twoez.zupzup.plogginglog.controller.dto.response.PloggingLogListResponse;
import com.twoez.zupzup.plogginglog.controller.dto.response.RecentPloggingLogResponse;
import com.twoez.zupzup.plogginglog.service.PloggingLogQueryService;
import com.twoez.zupzup.plogginglog.service.PloggingLogService;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/plogging-logs")
@RequiredArgsConstructor
public class PloggingLogController {

    private final PloggingLogQueryService ploggingLogQueryService;
    private final PloggingLogService ploggingLogService;

    @GetMapping("/period")
    public ApiResponse<List<PloggingLogListResponse>> ploggingListByPeriod(
            @RequestParam LocalDateTime startDate,
            @RequestParam LocalDateTime endDate,
            @AuthenticationPrincipal LoginUser loginUser) {
        return ApiResponse.ok(
                ploggingLogQueryService
                        .searchInPeriod(startDate, endDate, loginUser.getMemberId())
                        .stream()
                        .map(PloggingLogListResponse::from)
                        .toList());
    }

    @GetMapping("/days")
    public ApiResponse<List<PloggingLogListResponse>> ploggingListByDay(
            @RequestParam LocalDate date, @AuthenticationPrincipal LoginUser loginUser) {
        return ApiResponse.ok(
                ploggingLogQueryService.searchByDate(date, loginUser.getMemberId()).stream()
                        .map(PloggingLogListResponse::from)
                        .toList());
    }

    @GetMapping("/recent")
    public ApiResponse<RecentPloggingLogResponse> recentPloggingLogDetails(
            @AuthenticationPrincipal LoginUser loginUser) {
        return ApiResponse.ok(
                RecentPloggingLogResponse.from(
                        ploggingLogQueryService.searchRecentLog(loginUser.getMemberId())));
    }

    @PostMapping
    public ApiResponse<PloggingLogAddResponse> ploggingLogAdd(
            @Validated @RequestBody PloggingLogRequest request,
            @AuthenticationPrincipal LoginUser loginUser) {

        return ApiResponse.created(
                PloggingLogAddResponse.from(
                        ploggingLogService.add(request, loginUser.getMemberId())));
    }
}
