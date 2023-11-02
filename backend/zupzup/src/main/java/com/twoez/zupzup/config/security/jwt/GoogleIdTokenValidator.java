package com.twoez.zupzup.config.security.jwt;


import com.twoez.zupzup.config.security.oauth.GoogleOauthProperty;
import com.twoez.zupzup.member.domain.AuthUser;
import com.twoez.zupzup.member.domain.OauthProvider;
import com.twoez.zupzup.member.exception.OidcPublicKeyFeignException;
import com.twoez.zupzup.member.service.client.GoogleOauthClient;
import com.twoez.zupzup.member.service.dto.OidcPublicKeyList;
import feign.FeignException;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class GoogleIdTokenValidator extends AbstractIdTokenValidator {

    private static final String GOOGLE_ID_KEY = "sub";
    private static final String GOOGLE_NAME_KEY = "name";

    private final GoogleOauthClient googleOauthClient;

    public GoogleIdTokenValidator(
            JwtValidator jwtValidator,
            GoogleOauthProperty googleOauthProperty,
            GoogleOauthClient googleOauthClient) {
        super(jwtValidator, googleOauthProperty.toOidcProperty());
        this.googleOauthClient = googleOauthClient;
    }

    @Override
    public OidcPublicKeyList getOidcPublicKeys() {
        try {
            return googleOauthClient.getGoogleOidcPublicKeys();
        } catch (FeignException e) {
            e.printStackTrace();
            throw new OidcPublicKeyFeignException();
        }
    }

    @Override
    public AuthUser extractUserInfo(Map<String, Object> payload) {
        String oauthAccount = (String) payload.get(GOOGLE_ID_KEY);
        String userName = (String) payload.get(GOOGLE_NAME_KEY);
        return AuthUser.builder()
                .oauthProvider(OauthProvider.GOOGLE)
                .oauthAccount(oauthAccount)
                .name(userName)
                .build();
    }
}
