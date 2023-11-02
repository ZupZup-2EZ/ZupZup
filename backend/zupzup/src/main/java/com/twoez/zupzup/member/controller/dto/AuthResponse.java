package com.twoez.zupzup.member.controller.dto;


import com.twoez.zupzup.config.security.jwt.AuthorizationToken;
import lombok.Builder;

@Builder
public record AuthResponse(
        boolean isNewMember, String accessToken, String refreshToken, Long memberId) {

    public static AuthResponse from(AuthorizationToken authorizationToken, Long memberId) {
        return AuthResponse.builder()
                .isNewMember(false)
                .accessToken(authorizationToken.getAccessToken())
                .refreshToken(authorizationToken.getRefreshToken())
                .memberId(memberId)
                .build();
    }

    public static AuthResponse unregisteredUser(Long memberId) {
        return AuthResponse.builder().isNewMember(true).memberId(memberId).build();
    }
}
