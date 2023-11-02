package com.twoez.zupzup.config.jpa;


import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EnableJpaRepositories(
        basePackages = "com.twoez.zupzup",
        excludeFilters = {
            @ComponentScan.Filter(
                    type = FilterType.ASPECTJ,
                    pattern = "com.twoez.zupzup.*.repository.mongo.*"),
            @ComponentScan.Filter(
                    type = FilterType.ASPECTJ,
                    pattern = "com.twoez.zupzup.*.repository.redis.*")
        })
public class JpaConfig {}
