package com.twoez.zupzup.member.domain;


import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Embeddable
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OAuth {

    @Enumerated(EnumType.STRING)
    private AuthProvider oauthProvider;

    @Column(nullable = false)
    private String oauthAccount;

    public OAuth(AuthProvider oauthProvider, String oauthAccount) {
        this.oauthProvider = oauthProvider;
        this.oauthAccount = oauthAccount;
    }
}
