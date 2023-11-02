package com.twoez.zupzup.plogging.domain;


import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@RedisHash(value = "plogger")
public class Plogger {

    @Id private String id;

    private Long total;

    public Plogger(String id, Long total) {
        this.id = id;
        this.total = total;
    }

    public Plogger increase() {
        if (this.total == Integer.MAX_VALUE) {
            return this;
        }
        this.total++;
        return this;
    }

    public Plogger decrease() {
        if (this.total == 0) {
            return this;
        }
        this.total--;
        return this;
    }
}
