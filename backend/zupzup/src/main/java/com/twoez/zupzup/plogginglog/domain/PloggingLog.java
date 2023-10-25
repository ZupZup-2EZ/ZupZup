package com.twoez.zupzup.plogginglog.domain;


import com.twoez.zupzup.global.audit.BaseTime;
import com.twoez.zupzup.member.domain.Member;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import java.time.LocalDateTime;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class PloggingLog extends BaseTime {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false)
    private Long id;

    @Column(nullable = false)
    private Integer distance;

    @Column(nullable = false)
    private LocalDateTime startDateTime;

    @Column(nullable = false)
    private LocalDateTime endDateTime;

    @Column(nullable = false)
    private Integer calories;

    @Column(nullable = false)
    private Integer gatheredTrash;

    @Column(nullable = false)
    private Long coin;

    @Column(nullable = false)
    private String routeImageUrl;

    @Column(nullable = false)
    private Boolean isDeleted;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id")
    private Member member;

    @Builder
    public PloggingLog(
            Long id,
            Integer distance,
            LocalDateTime startDateTime,
            LocalDateTime endDateTime,
            Integer calories,
            Integer gatheredTrash,
            Long coin,
            String routeImageUrl,
            Boolean isDeleted,
            Member member) {
        this.id = id;
        this.distance = distance;
        this.startDateTime = startDateTime;
        this.endDateTime = endDateTime;
        this.calories = calories;
        this.gatheredTrash = gatheredTrash;
        this.coin = coin;
        this.routeImageUrl = routeImageUrl;
        this.isDeleted = isDeleted;
        this.member = member;
    }
}
