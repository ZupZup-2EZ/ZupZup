package com.twoez.zupzup.trashcan.controller;

import static com.twoez.zupzup.support.docs.ApiDocumentUtils.getDocumentRequest;
import static com.twoez.zupzup.support.docs.ApiDocumentUtils.getDocumentResponse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.twoez.zupzup.fixture.trashcan.TrashcanFixture;
import com.twoez.zupzup.support.docs.RestDocsTest;
import com.twoez.zupzup.trashcan.controller.dto.request.TrashcanListRequest;
import com.twoez.zupzup.trashcan.domain.Trashcan;
import com.twoez.zupzup.trashcan.service.TrashcanQueryService;
import java.math.BigDecimal;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

@WebMvcTest(TrashcanController.class)
public class TrashcanControllerTest extends RestDocsTest {

    @MockBean TrashcanQueryService trashcanQueryService;

    @Test
    @DisplayName("반경 100미터 이내 쓰레기통을을 조회한다.")
    void trashcanListByLocation() throws Exception {
        Trashcan trashcanOne =
                TrashcanFixture.NORMAL.getCustomTrashcan(
                        2L,
                        BigDecimal.valueOf(37.5011456828133),
                        BigDecimal.valueOf(127.0391649471062),
                        "바나");

        Trashcan trashcanTwo =
                TrashcanFixture.RECYCLE.getCustomTrashcan(
                        3L,
                        BigDecimal.valueOf(37.5008558904226),
                        BigDecimal.valueOf(127.0367305139974),
                        "역삼역");

        BigDecimal latitude = BigDecimal.valueOf(37.501285201600155);
        BigDecimal longitude = BigDecimal.valueOf(127.03957639050276);
        TrashcanListRequest request = new TrashcanListRequest(latitude, longitude);

        given(trashcanQueryService.findByLocation(any(BigDecimal.class), any(BigDecimal.class)))
                .willReturn(List.of(trashcanOne, trashcanTwo));

        ResultActions perform =
                mockMvc.perform(
                        get("/api/v1/trashcans")
                                .contextPath("/api")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(toJson(request)));

        // 수행 후 상태 예측
        perform.andExpect(status().isOk());

        // RestDocs 생성 부분
        perform.andDo(print())
                .andDo(
                        document(
                                "trashcan-list-by-location",
                                getDocumentRequest(),
                                getDocumentResponse()));
    }
}
