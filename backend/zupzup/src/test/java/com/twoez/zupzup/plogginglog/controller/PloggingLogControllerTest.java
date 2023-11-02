package com.twoez.zupzup.plogginglog.controller;

import static com.twoez.zupzup.support.docs.ApiDocumentUtils.getDocumentRequest;
import static com.twoez.zupzup.support.docs.ApiDocumentUtils.getDocumentResponse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.queryParameters;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.twoez.zupzup.fixture.member.MemberFixture;
import com.twoez.zupzup.fixture.plogginglog.PloggingLogFixture;
import com.twoez.zupzup.member.domain.Member;
import com.twoez.zupzup.plogginglog.controller.dto.request.PloggingLogRequest;
import com.twoez.zupzup.plogginglog.domain.PloggingLog;
import com.twoez.zupzup.plogginglog.service.PloggingLogQueryService;
import com.twoez.zupzup.plogginglog.service.PloggingLogService;
import com.twoez.zupzup.support.docs.RestDocsTest;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

@WebMvcTest(PloggingLogController.class)
class PloggingLogControllerTest extends RestDocsTest {

    @MockBean PloggingLogQueryService ploggingLogQueryService;
    @MockBean PloggingLogService ploggingLogService;
    Member member;

    @BeforeEach
    void initObjects() {
        this.member = MemberFixture.DEFAULT.getMember();
    }

    @Test
    @DisplayName("특정 기간의 플로깅 기록을 조회한다.")
    void floggingLogByStartDateAndEndDate() throws Exception {
        LocalDateTime now = LocalDateTime.now();
        PloggingLog ploggingLog =
                PloggingLogFixture.DEFAULT.getPloggingLogWithPeriod(now, now, member);
        given(
                        ploggingLogQueryService.searchInPeriod(
                                any(LocalDateTime.class),
                                any(LocalDateTime.class),
                                any(Long.class)))
                .willReturn(List.of(ploggingLog));

        ResultActions perform =
                mockMvc.perform(
                        get("/api/v1/plogging-logs/period")
                                .queryParam(
                                        "startDate", LocalDateTime.of(2023, 10, 1, 0, 0).toString())
                                .queryParam(
                                        "endDate", LocalDateTime.of(2023, 10, 3, 0, 0).toString())
                                .contentType(MediaType.APPLICATION_JSON));

        perform.andExpect(status().isOk());

        perform.andDo(print())
                .andDo(
                        document(
                                "plogginglog-by-period",
                                getDocumentRequest(),
                                getDocumentResponse(),
                                queryParameters(
                                        parameterWithName("startDate").description("시작 시간"),
                                        parameterWithName("endDate").description("종료 시간"))));
    }

    @Test
    @DisplayName("특정 일의 플로깅 기록을 조회한다.")
    void floggingLogByDate() throws Exception {
        LocalDateTime now = LocalDateTime.now();
        PloggingLog ploggingLog =
                PloggingLogFixture.DEFAULT.getPloggingLogWithPeriod(now, now, member);
        given(ploggingLogQueryService.searchByDate(any(LocalDate.class), any(Long.class)))
                .willReturn(List.of(ploggingLog));

        ResultActions perform =
                mockMvc.perform(
                        get("/api/v1/plogging-logs/days")
                                .queryParam("date", LocalDate.of(2023, 10, 1).toString())
                                .contentType(MediaType.APPLICATION_JSON));

        perform.andExpect(status().isOk());

        perform.andDo(print())
                .andDo(
                        document(
                                "plogginglog-by-date",
                                getDocumentRequest(),
                                getDocumentResponse(),
                                queryParameters(parameterWithName("date").description("조회일"))));
    }

    @Test
    @DisplayName("최근 플로깅 기록을 조회한다.")
    void recentFloggingLog() throws Exception {
        LocalDateTime now = LocalDateTime.now();
        PloggingLog ploggingLog =
                PloggingLogFixture.DEFAULT.getPloggingLogWithPeriod(now, now, member);
        given(ploggingLogQueryService.searchRecentLog(any(Long.class))).willReturn(ploggingLog);

        ResultActions perform =
                mockMvc.perform(
                        get("/api/v1/plogging-logs/recent")
                                .contentType(MediaType.APPLICATION_JSON));

        perform.andExpect(status().isOk());

        perform.andDo(print())
                .andDo(
                        document(
                                "plogginglog-by-recent",
                                getDocumentRequest(),
                                getDocumentResponse()));
    }

    @Test
    @DisplayName("플로깅 종료 시 해당 플로깅에 대한 기록을 저장한다.")
    void ploggingLogAddTest() throws Exception {

        PloggingLogRequest request = PloggingLogFixture.DEFAULT.getPloggingLogRequest();
        PloggingLog ploggingLog = PloggingLogFixture.DEFAULT.getPloggingLog();

        given(ploggingLogService.add(any(PloggingLogRequest.class), any(Long.class)))
                .willReturn(ploggingLog);

        ResultActions perform =
                mockMvc.perform(
                        post("/api/v1/plogging-logs")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(toJson(request)));

        perform.andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(HttpStatus.CREATED.value()))
                .andExpect(jsonPath("$.results.id").value(1L));

        perform.andDo(print())
                .andDo(document("plogginglog-add", getDocumentRequest(), getDocumentResponse()));
    }
}
