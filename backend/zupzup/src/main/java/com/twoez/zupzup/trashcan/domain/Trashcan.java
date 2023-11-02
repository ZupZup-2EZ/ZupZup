package com.twoez.zupzup.trashcan.domain;


import com.twoez.zupzup.global.audit.BaseTime;
import jakarta.persistence.*;
import java.math.BigDecimal;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Trashcan extends BaseTime {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "trashcan_id")
    private Long id;

    @Column(nullable = false, precision = 16, scale = 13)
    private BigDecimal latitude; // 위도

    @Column(nullable = false, precision = 16, scale = 13)
    private BigDecimal longitude; // 경도

    @Column(nullable = false)
    private String trashcanType;

    @Column(nullable = false)
    private String guName;

    @Column(nullable = false)
    private String roadName;

    @Column(nullable = false)
    private String address;

    @Column(nullable = false)
    private String locationType;

    @Column(nullable = false)
    private Boolean isDeleted;

    @Builder
    public Trashcan(
            Long id,
            BigDecimal latitude,
            BigDecimal longitude,
            String trashcanType,
            String guName,
            String roadName,
            String address,
            String locationType,
            Boolean isDeleted) {
        this.id = id;
        this.latitude = latitude;
        this.longitude = longitude;
        this.trashcanType = trashcanType;
        this.guName = guName;
        this.roadName = roadName;
        this.address = address;
        this.locationType = locationType;
        this.isDeleted = isDeleted;
    }
}
