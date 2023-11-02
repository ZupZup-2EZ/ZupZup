package com.twoez.zupzup.config.security.filter;


import com.twoez.zupzup.config.security.exception.InvalidAuthorizationHeaderException;
import com.twoez.zupzup.config.security.jwt.JwtValidator;
import com.twoez.zupzup.global.util.Assertion;
import com.twoez.zupzup.member.domain.LoginUser;
import com.twoez.zupzup.member.domain.mapper.LoginUserMapper;
import com.twoez.zupzup.member.service.MemberService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String GRANT_TYPE_BEARER = "Bearer ";

    private final JwtValidator jwtValidator;
    private final MemberService memberService;
    private final LoginUserMapper loginUserMapper;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        log.info("[Filter - START] JwtAuthFilter - {}", request.getRequestURI());

        // 1. Bearer 토큰 검증
        // 2. AccessToken 검증
        // 3. accessToken에서 Id 뽑아서 db에 저장된 유저 정보 검색
        // 4. 유저 정보를 LoginUser에 매핑
        // 5. LoginUser로 Authentication을 만들어서 Security Context에 저장

        getTokenFromHeader(request)
                .ifPresent(
                        (bearerToken) -> {
                            String token = validateBearerToken(bearerToken);
                            setAuthenticationInSecurityContext(token);
                        });

        doFilter(request, response, filterChain);
        log.info("[Filter - END] JwtAuthFilter");
    }

    private Optional<String> getTokenFromHeader(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(AUTHORIZATION_HEADER));
    }

    private String validateBearerToken(String bearerToken) {
        Assertion.with(bearerToken)
                .setValidation(this::isValidBearerToken)
                .validateOrThrow(InvalidAuthorizationHeaderException::new);
        return bearerToken.substring(GRANT_TYPE_BEARER.length());
    }

    private boolean isValidBearerToken(String bearerToken) {
        return StringUtils.hasText(bearerToken) && bearerToken.startsWith(GRANT_TYPE_BEARER);
    }

    private void setAuthenticationInSecurityContext(String token) {
        Long memberIdInAccessToken = jwtValidator.getMemberIdFromAccessToken(token);

        // TODO : 예외 write
        LoginUser loginUser =
                loginUserMapper.toLoginUser(memberService.findById(memberIdInAccessToken));

        SecurityContextHolder.getContext()
                .setAuthentication(
                        new UsernamePasswordAuthenticationToken(
                                loginUser, "", loginUser.getAuthorities()));
    }
}
