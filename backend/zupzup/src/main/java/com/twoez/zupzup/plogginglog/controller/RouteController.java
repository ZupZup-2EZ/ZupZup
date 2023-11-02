package com.twoez.zupzup.plogginglog.controller;


import com.twoez.zupzup.global.response.ApiResponse;
import com.twoez.zupzup.plogginglog.controller.dto.request.RouteAddRequest;
import com.twoez.zupzup.plogginglog.controller.dto.response.RouteDetailsResponse;
import com.twoez.zupzup.plogginglog.service.RouteService;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/routes")
@RequiredArgsConstructor
public class RouteController {

    private final RouteService routeService;

    @PostMapping("/{ploggingLogId}")
    public ApiResponse<?> routeAdd(
            @PathVariable @NotNull @Min(1L) Long ploggingLogId,
            @Validated @RequestBody RouteAddRequest request) {

        routeService.addRoute(request, ploggingLogId);
        return ApiResponse.created().build();
    }

    @GetMapping("/{ploggingLogId}")
    public ApiResponse<RouteDetailsResponse> routeDetails(
            @PathVariable @NotNull @Min(1L) Long ploggingLogId) {
        return ApiResponse.ok(RouteDetailsResponse.from(routeService.searchRoute(ploggingLogId)));
    }
}
