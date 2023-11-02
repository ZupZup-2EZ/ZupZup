package com.twoez.zupzup.member.service;


import com.twoez.zupzup.config.security.jwt.AuthorizationToken;
import com.twoez.zupzup.config.security.jwt.JwtProvider;
import com.twoez.zupzup.global.exception.HttpExceptionCode;
import com.twoez.zupzup.member.controller.dto.MemberHealthRequest;
import com.twoez.zupzup.member.domain.AuthUser;
import com.twoez.zupzup.member.domain.Member;
import com.twoez.zupzup.member.exception.MemberQueryException;
import com.twoez.zupzup.member.repository.MemberQueryRepository;
import com.twoez.zupzup.member.repository.MemberSpringDataRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class MemberService {

    private final JwtProvider jwtProvider;
    private final MemberQueryRepository memberQueryRepository;
    private final MemberSpringDataRepository memberSpringDataRepository;

    public Member save(AuthUser authUser) {
        return memberSpringDataRepository.save(authUser.toNewMember());
    }

    public Optional<Member> findMemberByOauth(AuthUser authUser) {
        return memberQueryRepository.findByOauth(authUser.getOauth());
    }

    public AuthorizationToken issueAuthorizationToken(Member member) {
        return jwtProvider.createAuthorizationToken(member.getId());
    }

    public AuthorizationToken issueAuthorizationToken(Long memberId) {
        Member member = findById(memberId);
        return jwtProvider.createAuthorizationToken(member.getId());
    }

    @Transactional
    public void modifyMemberHealth(MemberHealthRequest memberHealthRequest) {
        Long memberId = memberHealthRequest.memberId();
        Member member = findById(memberId);
        member.updateHealthInfo(
                memberHealthRequest.birthYear(),
                memberHealthRequest.gender(),
                memberHealthRequest.height(),
                memberHealthRequest.weight());
    }

    public Member findById(Long memberId) {
        log.info("findById Service - memberId : {}", memberId);
        return memberSpringDataRepository
                .findMemberByIsDeletedIsFalseAndIdEquals(memberId)
                .orElseThrow(() -> new MemberQueryException(HttpExceptionCode.MEMBER_NOT_FOUND));
    }
}
