package com.twoez.zupzup.plogginglog.repository;

import static com.twoez.zupzup.plogginglog.domain.QPloggingLog.ploggingLog;

import com.twoez.zupzup.global.querydsl.QuerydslRepositorySupport;
import com.twoez.zupzup.plogginglog.domain.PloggingLog;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional(readOnly = true)
public class PloggingLogQueryRepository extends QuerydslRepositorySupport {

    public PloggingLogQueryRepository() {
        super(PloggingLog.class);
    }

    public List<PloggingLog> findByBetweenStartDateAndEndDate(
            LocalDateTime startDate, LocalDateTime endDate, Long memberId) {
        return selectFrom(ploggingLog)
                .leftJoin(ploggingLog.member)
                .fetchJoin()
                .where(
                        ploggingLog
                                .member
                                .id
                                .eq(memberId)
                                .and(ploggingLog.startDateTime.after(startDate))
                                .and(ploggingLog.endDateTime.before(endDate)))
                .orderBy(ploggingLog.startDateTime.asc())
                .fetch();
    }

    public List<PloggingLog> findByDate(LocalDate date, Long memberId) {
        return selectFrom(ploggingLog)
                .leftJoin(ploggingLog.member)
                .fetchJoin()
                .where(
                        ploggingLog
                                .member
                                .id
                                .eq(memberId)
                                .and(ploggingLog.startDateTime.year().eq(date.getYear()))
                                .and(ploggingLog.startDateTime.month().eq(date.getMonthValue()))
                                .and(
                                        ploggingLog
                                                .startDateTime
                                                .dayOfMonth()
                                                .eq(date.getDayOfMonth())))
                .fetch();
    }

    public Optional<PloggingLog> findOneOrderByDateDesc(Long memberId) {
        return Optional.ofNullable(
                selectFrom(ploggingLog)
                        .leftJoin(ploggingLog.member)
                        .fetchJoin()
                        .where(ploggingLog.member.id.eq(memberId))
                        .orderBy(ploggingLog.startDateTime.desc())
                        .limit(1)
                        .fetchOne());
    }
}
