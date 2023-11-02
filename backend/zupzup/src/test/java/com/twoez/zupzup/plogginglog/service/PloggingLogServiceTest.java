package com.twoez.zupzup.plogginglog.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import com.twoez.zupzup.fixture.plogginglog.PloggingLogFixture;
import com.twoez.zupzup.member.repository.MemberRepository;
import com.twoez.zupzup.plogginglog.controller.dto.request.PloggingLogRequest;
import com.twoez.zupzup.plogginglog.domain.PloggingLog;
import com.twoez.zupzup.plogginglog.repository.PloggingLogRepository;
import java.time.LocalDateTime;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class PloggingLogServiceTest {

    @Mock PloggingLogRepository ploggingLogRepository;
    @Mock MemberRepository memberRepository;
    @InjectMocks PloggingLogService ploggingLogService;

    @Test
    @DisplayName("플로깅 기록을 저장한다.")
    void addPloggingLogTest() {
        PloggingLogRequest request =
                new PloggingLogRequest(
                        10,
                        LocalDateTime.of(2023, 10, 30, 0, 0),
                        LocalDateTime.of(2023, 10, 30, 2, 0),
                        7200,
                        600,
                        50,
                        200,
                        "https://image.com");

        PloggingLog ploggingLog = PloggingLogFixture.DEFAULT.getPloggingLog();
        given(ploggingLogRepository.save(any(PloggingLog.class))).willReturn(ploggingLog);
        given(memberRepository.findById(any(Long.class)))
                .willReturn(Optional.of(ploggingLog.getMember()));

        PloggingLog result = ploggingLogService.add(request, 1L);

        assertThat(result).isEqualTo(ploggingLog);
    }
}
