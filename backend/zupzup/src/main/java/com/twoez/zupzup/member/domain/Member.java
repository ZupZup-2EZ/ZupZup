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
import java.util.List;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.ColumnDefault;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Member extends BaseTime {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;

    @Embedded private Oauth oauth; // TODO oAuth 바꾸기

    @Column(nullable = false)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(length = 2)
    private Gender gender; // TODO char 타입 바꾸기

    @Column private Integer birthYear;

    @Column private Integer height;

    @Column private Integer weight;

    @Column(nullable = false)
    @ColumnDefault("0")
    private Long coin;

    @Enumerated(EnumType.STRING)
    @ElementCollection(fetch = FetchType.EAGER)
    private List<Role> role;

    @Column(nullable = false)
    @ColumnDefault("false")
    private Boolean isDeleted;

    @Builder
    public Member(
            Long id,
            Oauth oauth,
            String name,
            Gender gender,
            Integer birthYear,
            Integer height,
            Integer weight,
            Long coin,
            List<Role> role,
            Boolean isDeleted) {
        this.id = id;
        this.oauth = oauth;
        this.name = name;
        this.gender = gender;
        this.birthYear = birthYear;
        this.height = height;
        this.weight = weight;
        this.coin = coin;
        this.role = role;
        this.isDeleted = isDeleted;
    }

    public void updateHealthInfo(Integer birthYear, Gender gender, Integer height, Integer weight) {
        this.birthYear = birthYear;
        this.gender = gender;
        this.height = height;
        this.weight = weight;
    }

    public List<SimpleGrantedAuthority> getAuthorities() {
        return role.stream().map(Role::name).map(SimpleGrantedAuthority::new).toList();
    }
}
