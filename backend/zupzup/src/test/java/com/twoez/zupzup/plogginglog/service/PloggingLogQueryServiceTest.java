package com.twoez.zupzup.plogginglog.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import com.twoez.zupzup.member.domain.AuthProvider;
import com.twoez.zupzup.member.domain.Member;
import com.twoez.zupzup.member.domain.OAuth;
import com.twoez.zupzup.member.domain.Role;
import com.twoez.zupzup.plogginglog.domain.PloggingLog;
import com.twoez.zupzup.plogginglog.repository.PloggingLogQueryRepository;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class PloggingLogQueryServiceTest {

    @Mock PloggingLogQueryRepository ploggingLogQueryRepository;
    @InjectMocks PloggingLogQueryService ploggingLogQueryService;

    Member member;

    @BeforeEach
    void initObjects() {
        this.member =
                Member.builder()
                        .id(1L)
                        .oAuth(new OAuth(AuthProvider.GOOGLE, "1234567"))
                        .name("zupzup")
                        .gender("F")
                        .birthYear(2002)
                        .height(160)
                        .weight(50)
                        .coin(24L)
                        .isDeleted(false)
                        .role(List.of(Role.ROLE_USER))
                        .build();
    }

    @Test
    @DisplayName("기간 내의 플로깅 로그들을 가져온다.")
    void searchInPeriod() {
        LocalDateTime now = LocalDateTime.now();
        PloggingLog ploggingLog =
                PloggingLog.builder()
                        .id(1L)
                        .startDateTime(now)
                        .endDateTime(now)
                        .distance(12345)
                        .gatheredTrash(24)
                        .coin(240L)
                        .calories(240)
                        .member(member)
                        .routeImageUrl("https://image.com")
                        .isDeleted(false)
                        .build();
        given(
                        ploggingLogQueryRepository.findByBetweenStartDateAndEndDate(
                                any(LocalDateTime.class),
                                any(LocalDateTime.class),
                                any(Long.class)))
                .willReturn(List.of(ploggingLog));

        List<PloggingLog> ploggingLogs =
                ploggingLogQueryService.searchInPeriod(
                        LocalDateTime.now(), LocalDateTime.now().plusDays(2), 1L);

        assertThat(ploggingLogs).containsExactly(ploggingLog);
    }

    @Test
    @DisplayName("특정 일의 플로깅 로그들을 가져온다.")
    void searchByDate() {
        LocalDateTime now = LocalDateTime.now();
        PloggingLog ploggingLog =
                PloggingLog.builder()
                        .id(1L)
                        .startDateTime(now)
                        .endDateTime(now)
                        .distance(12345)
                        .gatheredTrash(24)
                        .coin(240L)
                        .calories(240)
                        .member(member)
                        .routeImageUrl("https://image.com")
                        .isDeleted(false)
                        .build();
        given(ploggingLogQueryRepository.findByDate(any(LocalDate.class), any(Long.class)))
                .willReturn(List.of(ploggingLog));

        List<PloggingLog> ploggingLogs = ploggingLogQueryService.searchByDate(LocalDate.now(), 1L);

        assertThat(ploggingLogs).containsExactly(ploggingLog);
    }

    @Test
    @DisplayName("최근 플로깅 로그를 가져온다.")
    void searchRecent() {
        LocalDateTime now = LocalDateTime.now();
        PloggingLog ploggingLog =
                PloggingLog.builder()
                        .id(1L)
                        .startDateTime(now)
                        .endDateTime(now)
                        .distance(12345)
                        .gatheredTrash(24)
                        .coin(240L)
                        .calories(240)
                        .member(member)
                        .routeImageUrl("https://image.com")
                        .isDeleted(false)
                        .build();
        given(ploggingLogQueryRepository.findOneOrderByDateDesc(any(Long.class)))
                .willReturn(Optional.ofNullable(ploggingLog));

        PloggingLog findPloggingLog = ploggingLogQueryService.searchRecentLog(1L);

        assertThat(findPloggingLog).isEqualTo(ploggingLog);
    }
}
