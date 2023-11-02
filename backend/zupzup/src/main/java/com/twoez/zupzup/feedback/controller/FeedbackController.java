package com.twoez.zupzup.feedback.controller;


import com.twoez.zupzup.feedback.controller.dto.FeedbackAddRequest;
import com.twoez.zupzup.feedback.controller.dto.FeedbackListResponse;
import com.twoez.zupzup.feedback.service.FeedbackService;
import com.twoez.zupzup.global.response.ApiResponse;
import com.twoez.zupzup.global.support.PageCollectors;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/v1/feedbacks")
public class FeedbackController {

    private final FeedbackService feedbackService;

    @PostMapping
    public ApiResponse<?> feedbackAdd(
            @Validated @RequestBody FeedbackAddRequest feedbackAddRequest) {

        feedbackService.add(feedbackAddRequest);
        return ApiResponse.created().build();
    }

    @GetMapping
    public ApiResponse<Page<FeedbackListResponse>> feedbackList(Pageable pageable) {

        return ApiResponse.ok(
                PageCollectors.convertContent(
                        feedbackService.searchAll(pageable), pageable, FeedbackListResponse::of));
    }
}
