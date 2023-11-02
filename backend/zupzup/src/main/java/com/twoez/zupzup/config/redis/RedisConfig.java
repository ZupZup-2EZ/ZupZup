package com.twoez.zupzup.config.redis;


import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;

@Configuration
@EnableRedisRepositories(basePackages = "com.twoez.zupzup.*.repository.redis")
public class RedisConfig {}
