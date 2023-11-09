package com.twoez.zupzup.config.security.handler;


import com.twoez.zupzup.config.security.jwt.AbstractJwtProvider;
import com.twoez.zupzup.config.security.jwt.Oauth2JwtProvider;
import com.twoez.zupzup.config.security.jwt.OidcJwtProvider;
import com.twoez.zupzup.member.domain.OauthProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class Oauth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final Oauth2JwtProvider oauth2JwtProvider;
    private final OidcJwtProvider oidcJwtProvider;

    @Value("${client.url}")
    private String clientUrl;

    @Value("${client.redirect.login-success}")
    private String redirectUrl;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        // 1. authToken 발급
        // 2. /login-success 로 Redirect
        // ** 원래는 idToken을 프론트에서 받아와서 넘겨주면서 백에서 idToken, Provider를 받아서 처리하는 방식
        // ** 그런데 spring security를 활용하기 때문에 url에 accessToken과 refreshToken을 노출시키지 않기 위해서 임시 토큰인
        // authToken 발급
        // ** 이 때 authToken 안에는 Provider로 부터 발급받은 idToken이 payload에 있다.
        // ** url로 밖에 전달할 수 없는 이유는 Redirect이기 때문
        // ** 프론트의 요청을 받기 위해 authToken과 provider를 redirect로 넘겨주고 다시 받아 로그인 및 회원가입 처리

        log.info("onAuthenticationSuccess called");

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String authToken;
        OauthProvider oauthProvider;
        if (oAuth2User instanceof OidcUser) {
            authToken = oidcJwtProvider.createAuthToken(oAuth2User);
            oauthProvider = OauthProvider.findByIss(((OidcUser) oAuth2User).getIssuer().toString());
        } else {
            authToken = oauth2JwtProvider.createAuthToken(oAuth2User);
            oauthProvider = OauthProvider.findByIss(oAuth2User.getName());
        }
        log.info("{}", oAuth2User.getAttributes());

        String loginSuccessRedirectUrl =
                clientUrl
                        + redirectUrl
                        + "?token="
                        + authToken
                        + "&provider="
                        + oauthProvider.getProvider();
        getRedirectStrategy().sendRedirect(request, response, loginSuccessRedirectUrl);

        super.onAuthenticationSuccess(request, response, authentication);
    }
}
