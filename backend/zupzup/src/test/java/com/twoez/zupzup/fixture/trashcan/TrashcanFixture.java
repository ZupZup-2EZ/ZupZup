package com.twoez.zupzup.fixture.trashcan;


import com.twoez.zupzup.trashcan.domain.Trashcan;
import java.math.BigDecimal;

public enum TrashcanFixture {
    NORMAL(
            1L,
            BigDecimal.valueOf(37.501285201600155),
            BigDecimal.valueOf(127.03957639050276),
            "일반",
            "멀캠",
            "멀캠",
            "멀캠",
            "상가지역",
            false),

    RECYCLE(
            1L,
            BigDecimal.valueOf(37.501285201600155),
            BigDecimal.valueOf(127.03957639050276),
            "재활용",
            "멀캠",
            "멀캠",
            "멀캠",
            "상가지역",
            false);

    private Long id;

    private BigDecimal latitude; // 위도

    private BigDecimal longitude; // 경도

    private String trashcanType;

    private String guName;

    private String roadName;

    private String address;

    private String locationType;

    private Boolean isDeleted;

    TrashcanFixture(
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

    public Trashcan getTrashcan() {
        return Trashcan.builder()
                .id(id)
                .latitude(latitude)
                .longitude(longitude)
                .trashcanType(trashcanType)
                .guName(guName)
                .roadName(roadName)
                .address(address)
                .locationType(locationType)
                .isDeleted(isDeleted)
                .build();
    }

    public Trashcan getCustomTrashcan(
            Long id, BigDecimal latitude, BigDecimal longitude, String guName) {
        return Trashcan.builder()
                .id(id)
                .latitude(latitude)
                .longitude(longitude)
                .trashcanType(trashcanType)
                .guName(guName)
                .roadName(roadName)
                .address(address)
                .locationType(locationType)
                .isDeleted(isDeleted)
                .build();
    }
}
