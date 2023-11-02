package com.twoez.zupzup.plogginglog.service;


import com.twoez.zupzup.global.exception.HttpExceptionCode;
import com.twoez.zupzup.member.exception.MemberQueryException;
import com.twoez.zupzup.member.repository.MemberRepository;
import com.twoez.zupzup.plogginglog.controller.dto.request.PloggingLogRequest;
import com.twoez.zupzup.plogginglog.domain.PloggingLog;
import com.twoez.zupzup.plogginglog.repository.PloggingLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class PloggingLogService {

    private final PloggingLogRepository ploggingLogRepository;
    private final MemberRepository memberRepository;

    public PloggingLog add(PloggingLogRequest request, Long memberId) {

        return ploggingLogRepository.save(
                request.toEntity(
                        memberRepository
                                .findById(memberId)
                                .orElseThrow(
                                        () ->
                                                new MemberQueryException(
                                                        HttpExceptionCode.MEMBER_NOT_FOUND))));
    }
}
