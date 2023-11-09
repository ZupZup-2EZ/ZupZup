package com.twoez.zupzup.member.domain;


import com.twoez.zupzup.member.exception.OauthProviderNotFoundException;
import java.util.Arrays;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter
public enum OauthProvider {
    KAKAO("KAKAO", "https://kauth.kakao.com"),
    GOOGLE("GOOGLE", "https://accounts.google.com"),
    NAVER("NAVER", "https://nid.naver.com");

    private static final String GOOGLE_OTHER_ISS = "accounts.google.com";
    private String provider;
    private String iss;

    OauthProvider(String provider, String iss) {
        this.provider = provider;
        this.iss = iss;
    }

    public static OauthProvider findByIss(String iss) {

        log.info(iss);
        if (iss.equals(GOOGLE_OTHER_ISS)) {
            return OauthProvider.GOOGLE;
        }

        return Arrays.stream(OauthProvider.values())
                .filter((provider) -> iss.equals(provider.iss))
                .findFirst()
                .orElseThrow(OauthProviderNotFoundException::new);
    }
}
