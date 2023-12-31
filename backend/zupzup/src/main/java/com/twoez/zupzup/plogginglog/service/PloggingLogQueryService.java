package com.twoez.zupzup.plogginglog.service;


import com.twoez.zupzup.global.exception.plogginglog.TotalPloggingLogNotFoundException;
import com.twoez.zupzup.global.exception.plogginglog.TotalTrashNotFoundException;
import com.twoez.zupzup.member.domain.Member;
import com.twoez.zupzup.plogginglog.domain.PloggingLog;
import com.twoez.zupzup.plogginglog.domain.TotalPloggingLog;
import com.twoez.zupzup.plogginglog.domain.TotalTrash;
import com.twoez.zupzup.plogginglog.repository.PloggingLogQueryRepository;
import com.twoez.zupzup.plogginglog.repository.TotalPloggingLogRepository;
import com.twoez.zupzup.plogginglog.repository.TotalTrashRepository;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class PloggingLogQueryService {

    private final PloggingLogQueryRepository ploggingLogQueryRepository;
    private final TotalPloggingLogRepository totalPloggingLogRepository;
    private final TotalTrashRepository totalTrashRepository;

    public Map<LocalDate, Boolean> searchInMonthDistinct(LocalDate date, Long memberId) {
        return ploggingLogQueryRepository.findByMonth(date, memberId).stream()
                .map(ploggingLog -> ploggingLog.getStartDateTime().toLocalDate())
                .distinct()
                .collect(Collectors.toMap(e -> e, e -> true));
    }

    public List<PloggingLog> searchInPeriod(
            LocalDateTime startDate, LocalDateTime endDate, Long memberId) {
        return ploggingLogQueryRepository.findByBetweenStartDateAndEndDate(
                startDate, endDate, memberId);
    }

    public List<PloggingLog> searchByDate(LocalDate date, Long memberId) {
        return ploggingLogQueryRepository.findByDate(date, memberId);
    }

    public Optional<PloggingLog> searchRecentLog(Long memberId) {
        return ploggingLogQueryRepository.findOneOrderByDateDesc(memberId);
    }

    public TotalPloggingLog searchTotalPloggingLog(Member member) {

        return totalPloggingLogRepository
                .findByMemberId(member.getId())
                .orElseThrow(TotalPloggingLogNotFoundException::new);
    }

    public TotalTrash searchTotalTrash(Member member) {

        return totalTrashRepository
                .findByMemberId(member.getId())
                .orElseThrow(TotalTrashNotFoundException::new);
    }
}
