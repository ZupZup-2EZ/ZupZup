package com.twoez.zupzup.member.domain;


import java.util.List;
import lombok.Builder;
import lombok.ToString;

@Builder
@ToString
public class AuthUser {

    private OauthProvider oauthProvider;
    private String oauthAccount;
    private String name;

    public AuthUser(OauthProvider oauthProvider, String oauthAccount, String name) {
        this.oauthProvider = oauthProvider;
        this.oauthAccount = oauthAccount;
        this.name = name;
    }

    public Oauth getOauth() {
        return new Oauth(oauthProvider, oauthAccount);
    }

    public Member toNewMember() {
        return Member.builder()
                .oauth(getOauth())
                .name(name)
                .coin(0L)
                .role(List.of(Role.ROLE_USER))
                .isDeleted(false)
                .build();
    }
}
