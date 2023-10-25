package com.twoez.zupzup.member.repository;


import com.twoez.zupzup.member.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {}
