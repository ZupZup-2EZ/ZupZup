package com.twoez.zupzup;


import com.twoez.zupzup.config.security.jwt.JwtProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
@EnableConfigurationProperties({JwtProperty.class})
public abstract class IntegrationTestSupport {}
