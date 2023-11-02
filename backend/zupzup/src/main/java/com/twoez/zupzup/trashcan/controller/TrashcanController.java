package com.twoez.zupzup.trashcan.controller;


import com.twoez.zupzup.global.response.ApiResponse;
import com.twoez.zupzup.trashcan.controller.dto.request.TrashcanListRequest;
import com.twoez.zupzup.trashcan.controller.dto.response.TrashcanListResponse;
import com.twoez.zupzup.trashcan.service.TrashcanQueryService;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/trashcans")
@RequiredArgsConstructor
public class TrashcanController {

    private final TrashcanQueryService trashcanQueryService;

    @GetMapping
    public ApiResponse<List<TrashcanListResponse>> findByLocation(
            @Validated @RequestBody TrashcanListRequest request) {
        return ApiResponse.ok(
                trashcanQueryService
                        .findByLocation(request.currentLatitude(), request.currentLongitude())
                        .stream()
                        .map(TrashcanListResponse::from)
                        .toList());
    }
}
