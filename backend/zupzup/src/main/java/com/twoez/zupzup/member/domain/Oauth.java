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
public class Oauth {

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private OauthProvider oauthProvider;

    @Column(nullable = false)
    private String oauthAccount;

    public Oauth(OauthProvider oauthProvider, String oauthAccount) {
        this.oauthProvider = oauthProvider;
        this.oauthAccount = oauthAccount;
    }
}
