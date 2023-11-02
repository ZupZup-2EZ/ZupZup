package com.twoez.zupzup.member.service.client;


import com.twoez.zupzup.member.service.dto.OidcPublicKeyList;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(name = "GoogleOauthClient", url = "https://www.googleapis.com")
@Component
public interface GoogleOauthClient {

    @Cacheable(value = "googlePublicKeys")
    @GetMapping("/oauth2/v3/certs")
    OidcPublicKeyList getGoogleOidcPublicKeys();
}
