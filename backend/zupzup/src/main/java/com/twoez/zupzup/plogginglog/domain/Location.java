package com.twoez.zupzup.plogginglog.domain;


import java.math.BigDecimal;
import lombok.Getter;

@Getter
public class Location {

    private BigDecimal latitude;
    private BigDecimal longitude;

    public Location(BigDecimal latitude, BigDecimal longitude) {
        this.latitude = latitude;
        this.longitude = longitude;
    }

    public static Location of(BigDecimal latitude, BigDecimal longitude) {
        return new Location(latitude, longitude);
    }
}
