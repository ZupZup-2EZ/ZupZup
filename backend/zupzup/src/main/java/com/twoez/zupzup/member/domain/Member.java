package com.twoez.zupzup.member.domain;


import com.twoez.zupzup.global.audit.BaseTime;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import java.util.ArrayList;
import java.util.List;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Member extends BaseTime {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Embedded private OAuth oAuth;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String gender;

    @Column(nullable = false)
    private Integer birthYear;

    @Column(nullable = false)
    private Integer height;

    @Column(nullable = false)
    private Integer weight;

    @Column(nullable = false)
    private Long coin;

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    private List<Role> role = new ArrayList<>();

    @Column(nullable = false)
    private Boolean isDeleted;

    @Builder
    public Member(
            Long id,
            OAuth oAuth,
            String name,
            String gender,
            Integer birthYear,
            Integer height,
            Integer weight,
            Long coin,
            List<Role> role,
            Boolean isDeleted) {
        this.id = id;
        this.oAuth = oAuth;
        this.name = name;
        this.gender = gender;
        this.birthYear = birthYear;
        this.height = height;
        this.weight = weight;
        this.coin = coin;
        this.role = new ArrayList<>(role);
        this.isDeleted = isDeleted;
    }
}
