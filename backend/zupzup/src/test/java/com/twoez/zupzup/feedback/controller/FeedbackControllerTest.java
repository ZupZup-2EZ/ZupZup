package com.twoez.zupzup.feedback.controller;

import static com.twoez.zupzup.support.docs.ApiDocumentUtils.getDocumentRequest;
import static com.twoez.zupzup.support.docs.ApiDocumentUtils.getDocumentResponse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.queryParameters;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.twoez.zupzup.feedback.controller.dto.FeedbackAddRequest;
import com.twoez.zupzup.feedback.domain.Feedback;
import com.twoez.zupzup.feedback.service.FeedbackService;
import com.twoez.zupzup.support.docs.RestDocsTest;
import java.util.Comparator;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.support.PageableExecutionUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

@WebMvcTest(FeedbackController.class)
public class FeedbackControllerTest extends RestDocsTest {

    @MockBean FeedbackService feedbackService;

    @Test
    @DisplayName("사용자는 피드백을 작성할 수 있다.")
    void feedbackAddTest() throws Exception {

        FeedbackAddRequest request = new FeedbackAddRequest("너무 좋은 어플이에요");

        feedbackService.add(any(FeedbackAddRequest.class));

        ResultActions perform =
                mockMvc.perform(
                        post("/api/v1/feedbacks")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(toJson(request)));

        perform.andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(HttpStatus.CREATED.value()));

        perform.andDo(print())
                .andDo(document("feedback-add", getDocumentRequest(), getDocumentResponse()));
    }

    @Test
    @DisplayName("관리자는 피드백 리스트를 조회할 수 있다.")
    void feedbackListTest() throws Exception {

        List<Feedback> feedbacks =
                IntStream.range(1, 21)
                        .mapToObj(idx -> new Feedback((long) idx, "너무 좋아요!" + idx))
                        .toList();

        Pageable pageable = PageRequest.of(0, 5, Sort.by("id").descending());

        given(feedbackService.searchAll(any(Pageable.class)))
                .willReturn(
                        PageableExecutionUtils.getPage(
                                feedbacks.stream()
                                        .sorted(
                                                Comparator.comparingLong(Feedback::getId)
                                                        .reversed())
                                        .limit(5)
                                        .toList(),
                                pageable,
                                feedbacks::size));

        ResultActions perform =
                mockMvc.perform(
                        get("/api/v1/feedbacks")
                                .contentType(MediaType.APPLICATION_JSON)
                                .queryParam("page", "0")
                                .queryParam("size", "5"));

        perform.andExpect(status().isOk())
                .andExpect(jsonPath("$.results.content[0].id").value(20L));

        perform.andDo(print())
                .andDo(
                        document(
                                "feedback-list",
                                getDocumentRequest(),
                                getDocumentResponse(),
                                queryParameters(
                                        parameterWithName("page").description("페이지 번호"),
                                        parameterWithName("size").description("페이지 사이즈"))));
    }
}
