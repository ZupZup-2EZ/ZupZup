package com.twoez.zupzup.member.repository;


import com.twoez.zupzup.member.domain.Member;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberSpringDataRepository extends JpaRepository<Member, Long> {
    Optional<Member> findMemberByIsDeletedIsFalseAndIdEquals(Long memberId);
}
