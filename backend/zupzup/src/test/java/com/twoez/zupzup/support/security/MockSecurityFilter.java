package com.twoez.zupzup.support.security;


import com.twoez.zupzup.config.security.jwt.ExpiredTokenUser;
import com.twoez.zupzup.member.domain.Gender;
import com.twoez.zupzup.member.domain.LoginUser;
import com.twoez.zupzup.member.domain.Member;
import com.twoez.zupzup.member.domain.Oauth;
import com.twoez.zupzup.member.domain.OauthProvider;
import com.twoez.zupzup.member.domain.Role;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

public class MockSecurityFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) {}

    @Override
    public void destroy() {
        SecurityContextHolder.clearContext();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        if (httpRequest.getRequestURI().equals("/api/v1/auth/re-issue")) {
            SecurityContextHolder.getContext()
                    .setAuthentication(
                            new UsernamePasswordAuthenticationToken(
                                    new ExpiredTokenUser(1L), "password", new ArrayList<>()));
            chain.doFilter(request, response);
            return;
        }

        Member member = createMember();

        LoginUser loginUser =
                new LoginUser(
                        member,
                        new HashMap<>(Map.of("id", member.getId())),
                        member.getAuthorities());

        SecurityContextHolder.getContext()
                .setAuthentication(
                        new UsernamePasswordAuthenticationToken(
                                loginUser, "password", loginUser.getAuthorities()));

        chain.doFilter(request, response);
    }

    private Member createMember() {
        LocalDateTime now = LocalDateTime.now();
        Oauth oauth = new Oauth(OauthProvider.GOOGLE, "1234567");
        return Member.builder()
                .id(1L)
                .oauth(oauth)
                .name("mock")
                .gender(Gender.M)
                .birthYear(2000)
                .height(180)
                .weight(56)
                .coin(100L)
                .isDeleted(false)
                .role(List.of(Role.ROLE_USER))
                .build();
    }
}
