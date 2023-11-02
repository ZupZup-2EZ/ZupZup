package com.twoez.zupzup.plogging.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;

import com.twoez.zupzup.plogging.domain.Plogger;
import com.twoez.zupzup.plogging.repository.redis.PloggingRedisRepository;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class PloggingServiceTest {

    @Mock PloggingRedisRepository ploggingRedisRepository;
    @InjectMocks PloggingService ploggingService;

    private final String TOTAL_PLOGGER = "total_plogger";

    @Test
    @DisplayName("현재 플로거를 1명 증가시킨다.")
    void increaseTotalPloggerTest() {
        Plogger plogger = new Plogger(TOTAL_PLOGGER, 1L);

        given(ploggingRedisRepository.findById(TOTAL_PLOGGER)).willReturn(Optional.of(plogger));
        given(ploggingRedisRepository.save(plogger)).willReturn(plogger);

        Plogger result = ploggingService.increaseTotalPlogger();

        assertThat(result.getTotal()).isEqualTo(2L);
    }

    @Test
    @DisplayName("현재 플로거를 1명 감소시킨다.")
    void decreaseTotalPloggerTest() {
        Plogger plogger = new Plogger(TOTAL_PLOGGER, 1L);

        given(ploggingRedisRepository.findById(TOTAL_PLOGGER)).willReturn(Optional.of(plogger));
        given(ploggingRedisRepository.save(plogger)).willReturn(plogger);

        Plogger result = ploggingService.decreaseTotalPlogger();

        assertThat(result.getTotal()).isEqualTo(0L);
    }
}
