package com.twoez.zupzup.trashcan.repository;

import static com.twoez.zupzup.trashcan.domain.QTrashcan.trashcan;

import com.querydsl.core.types.dsl.Expressions;
import com.twoez.zupzup.global.querydsl.QuerydslRepositorySupport;
import com.twoez.zupzup.trashcan.domain.Trashcan;
import java.math.BigDecimal;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional(readOnly = true)
@Slf4j
public class TrashcanQueryRepository extends QuerydslRepositorySupport {

    public TrashcanQueryRepository() {
        super(Trashcan.class);
    }

    public List<Trashcan> findByLocation(BigDecimal latitude, BigDecimal longitude) {
        log.info("레포지토리 호출");
        return selectFrom(trashcan)
                .where(
                        (Expressions.numberTemplate(
                                        Long.class,
                                        "ST_Distance_Sphere({0}, {1})",
                                        Expressions.numberTemplate(
                                                Long.class, "POINT({0},{1})", longitude, latitude),
                                        Expressions.numberTemplate(
                                                Long.class,
                                                "POINT({0},{1})",
                                                trashcan.longitude,
                                                trashcan.latitude)))
                                .loe(3000L))
                .fetch();
    }
}
