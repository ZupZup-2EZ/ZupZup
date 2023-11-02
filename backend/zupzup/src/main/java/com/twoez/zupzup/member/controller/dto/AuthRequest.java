package com.twoez.zupzup.member.controller.dto;


import com.twoez.zupzup.member.domain.OauthProvider;
import jakarta.validation.constraints.NotBlank;

public record AuthRequest(OauthProvider oauthProvider, @NotBlank String authToken) {}
