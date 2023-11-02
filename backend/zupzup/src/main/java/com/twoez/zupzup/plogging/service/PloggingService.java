package com.twoez.zupzup.plogging.service;


import com.twoez.zupzup.plogging.domain.Plogger;
import com.twoez.zupzup.plogging.repository.redis.PloggingRedisRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class PloggingService {

    private final PloggingRedisRepository ploggerRedisRepository;
    private static final String TOTAL_PLOGGER = "total_plogger";

    @Transactional
    public Plogger increaseTotalPlogger() {

        return ploggerRedisRepository.save(
                ploggerRedisRepository
                        .findById(TOTAL_PLOGGER)
                        .map(Plogger::increase)
                        .orElse(new Plogger(TOTAL_PLOGGER, 1L)));
    }

    @Transactional
    public Plogger decreaseTotalPlogger() {

        return ploggerRedisRepository.save(
                ploggerRedisRepository
                        .findById(TOTAL_PLOGGER)
                        .map(Plogger::decrease)
                        .orElse(new Plogger(TOTAL_PLOGGER, 0L)));
    }

    public Plogger searchTotalPlogger() {

        return ploggerRedisRepository
                .findById(TOTAL_PLOGGER)
                .orElse(new Plogger(TOTAL_PLOGGER, 0L));
    }
}
