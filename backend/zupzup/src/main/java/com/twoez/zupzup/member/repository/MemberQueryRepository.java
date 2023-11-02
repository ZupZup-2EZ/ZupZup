package com.twoez.zupzup.member.repository;


import com.twoez.zupzup.global.querydsl.QuerydslRepositorySupport;
import com.twoez.zupzup.member.domain.Member;
import com.twoez.zupzup.member.domain.Oauth;
import com.twoez.zupzup.member.domain.QMember;
import jakarta.persistence.EntityManager;
import java.util.Optional;
import org.springframework.stereotype.Repository;

@Repository
public class MemberQueryRepository extends QuerydslRepositorySupport {

    private final QMember member = QMember.member;

    public MemberQueryRepository(EntityManager em) {
        super(Member.class);
    }

    public Optional<Member> findByOauth(Oauth oauth) {
        Member searchedMember =
                selectFrom(member)
                        .where(member.oauth.eq(oauth).and(member.isDeleted.isFalse()))
                        .fetchOne();
        return Optional.ofNullable(searchedMember);
    }
}
