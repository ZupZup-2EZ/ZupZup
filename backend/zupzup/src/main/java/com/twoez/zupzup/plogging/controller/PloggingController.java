package com.twoez.zupzup.plogging.controller;


import com.twoez.zupzup.global.response.ApiResponse;
import com.twoez.zupzup.plogging.controller.dto.PloggerResponse;
import com.twoez.zupzup.plogging.service.PloggingService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/v1/ploggings")
public class PloggingController {

    private final PloggingService ploggingService;

    @PutMapping("/start")
    public ApiResponse<PloggerResponse> ploggerAdd() {

        return ApiResponse.ok(PloggerResponse.from(ploggingService.increaseTotalPlogger()));
    }

    @PutMapping("/finish")
    public ApiResponse<PloggerResponse> ploggerRemove() {

        return ApiResponse.ok(PloggerResponse.from(ploggingService.decreaseTotalPlogger()));
    }

    @GetMapping("/number-of-users")
    public ApiResponse<PloggerResponse> ploggerDetails() {

        return ApiResponse.ok(PloggerResponse.from(ploggingService.searchTotalPlogger()));
    }
}
