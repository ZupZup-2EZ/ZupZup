package com.twoez.zupzup.plogging.controller;

import static com.twoez.zupzup.support.docs.ApiDocumentUtils.getDocumentRequest;
import static com.twoez.zupzup.support.docs.ApiDocumentUtils.getDocumentResponse;
import static org.mockito.BDDMockito.given;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.twoez.zupzup.fixture.member.MemberFixture;
import com.twoez.zupzup.member.domain.Member;
import com.twoez.zupzup.plogging.service.PloggingService;
import com.twoez.zupzup.support.docs.RestDocsTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

@WebMvcTest(PloggingController.class)
class PloggingControllerTest extends RestDocsTest {

    @MockBean PloggingService ploggingService;

    Member member;

    @BeforeEach
    void initObjects() {
        this.member = MemberFixture.DEFAULT.getMember();
    }

    @Test
    @DisplayName("사용자 플로깅 시작 버튼을 누르면, 전체 플로거의 수가 1 증가한다.")
    void ploggerAddTest() throws Exception {

        Long total = 0L;
        given(ploggingService.add(member.getId())).willReturn(total + 1L);

        ResultActions perform =
                mockMvc.perform(
                        post("/api/v1/ploggings/start").contentType(MediaType.APPLICATION_JSON));
        perform.andExpect(status().isOk()).andExpect(jsonPath("$.results.totalPlogger").value(1L));

        perform.andDo(print())
                .andDo(document("plogger-add", getDocumentRequest(), getDocumentResponse()));
    }

    @Test
    @DisplayName("사용자 플로깅 시작 버튼을 누르면, 전체 플로거의 수가 1 감소한다.")
    void ploggerRemoveTest() throws Exception {

        Long total = 1L;

        given(ploggingService.remove(member.getId())).willReturn(total - 1L);

        ResultActions perform =
                mockMvc.perform(
                        delete("/api/v1/ploggings/finish").contentType(MediaType.APPLICATION_JSON));

        perform.andExpect(status().isOk()).andExpect(jsonPath("$.results.totalPlogger").value(0L));

        perform.andDo(print())
                .andDo(document("plogger-remove", getDocumentRequest(), getDocumentResponse()));
    }

    @Test
    @DisplayName("전체 플로거의 수는 0 이하로 감소하지 않는다.")
    void ploggerRemoveExceptionTest() throws Exception {

        Long total = 0L;

        given(ploggingService.remove(member.getId())).willReturn(total);

        ResultActions perform =
                mockMvc.perform(
                        delete("/api/v1/ploggings/finish").contentType(MediaType.APPLICATION_JSON));

        perform.andExpect(status().isOk()).andExpect(jsonPath("$.results.totalPlogger").value(0L));

        perform.andDo(print())
                .andDo(
                        document(
                                "plogger-remove-exception",
                                getDocumentRequest(),
                                getDocumentResponse()));
    }

    @Test
    @DisplayName("전체 플로거의 수를 조회한다.")
    void ploggerDetailsTest() throws Exception {
        Long total = 10L;

        given(ploggingService.count()).willReturn(total);

        ResultActions perform =
                mockMvc.perform(
                        get("/api/v1/ploggings/number-of-users")
                                .contentType(MediaType.APPLICATION_JSON));

        perform.andExpect(status().isOk()).andExpect(jsonPath("$.results.totalPlogger").value(10L));

        perform.andDo(print())
                .andDo(document("plogger-details", getDocumentRequest(), getDocumentResponse()));
    }
}
