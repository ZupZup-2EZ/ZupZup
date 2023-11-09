package com.twoez.zupzup.config.security;


import com.twoez.zupzup.config.security.filter.ExceptionHandlerFilter;
import com.twoez.zupzup.config.security.filter.JwtAuthenticationFilter;
import com.twoez.zupzup.config.security.handler.DefaultAccessDeniedHandler;
import com.twoez.zupzup.config.security.handler.DefaultAuthenticationEntryPoint;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final DefaultAccessDeniedHandler accessDeniedHandler;
    private final DefaultAuthenticationEntryPoint authenticationEntryPoint;
    private final OidcUserService oidcUserService;
    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService;
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ExceptionHandlerFilter exceptionHandlerFilter;

    @Value("${client.url}")
    private String clientUrl;

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web ->
                web.ignoring()
                        .requestMatchers(
                                new AntPathRequestMatcher("/h2-console/**"),
                                new AntPathRequestMatcher("/favicon.ico"));
    }

    // TODO : 없는 경로로 요청왔을 때 Exception Handling?? 로그를 찍어야 함
    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity httpSecurity, HandlerMappingIntrospector introspector) throws Exception {
        log.info("Security filter chain Setting");
        return httpSecurity
                .exceptionHandling(
                        config ->
                                config.accessDeniedHandler(accessDeniedHandler)
                                        .authenticationEntryPoint(authenticationEntryPoint))
                .cors(config -> config.configurationSource(corsConfigurationSource()))
                .csrf(CsrfConfigurer::disable)
                .authorizeHttpRequests(
                        request ->
                                request.requestMatchers(
                                                new MvcRequestMatcher(introspector, "login/**"),
                                                new MvcRequestMatcher(introspector, "error"),
                                                new MvcRequestMatcher(introspector, "api/v1/auth"),
                                                new MvcRequestMatcher(introspector, "actuator/**"),
                                                new MvcRequestMatcher(
                                                        introspector, "api/v1/members/register"),
                                                new MvcRequestMatcher(
                                                        introspector, "api/v1/docs/api"))
                                        .permitAll()
                                        .requestMatchers(
                                                new MvcRequestMatcher(introspector, "api/**"))
                                        .authenticated()
                                        .anyRequest()
                                        .authenticated())
                .oauth2Login(
                        config ->
                                config.authorizationEndpoint(
                                                oauthConfig ->
                                                        oauthConfig.baseUri(
                                                                "/oauth2/authorization"))
                                        .userInfoEndpoint(
                                                endpointConfig ->
                                                        endpointConfig
                                                                .oidcUserService(oidcUserService)
                                                                .userService(oAuth2UserService))
                                        .successHandler(successHandler)
                                        .failureHandler(failureHandler))
                .sessionManagement(
                        config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthenticationFilter, OAuth2LoginAuthenticationFilter.class)
                .addFilterBefore(exceptionHandlerFilter, JwtAuthenticationFilter.class)
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(clientUrl));
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");

        // 어떤 컨트롤러(url-based)에 위의 cors 설정을 할 것인지 설정
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
