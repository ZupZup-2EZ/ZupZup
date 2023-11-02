package com.twoez.zupzup.config.security.oauth;


import com.twoez.zupzup.config.security.jwt.OidcProperty;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GoogleOauthProperty {

    @Value("${oidc.google.iss}")
    private String iss;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String aud;

    public OidcProperty toOidcProperty() {
        return new OidcProperty(iss, aud);
    }
}
