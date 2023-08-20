package com.example.sstest.domain;

import lombok.*;

import javax.persistence.*;
import java.io.Serializable;

@Table(name = "member")
@ToString
@Entity
@Getter
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Member implements Serializable {
    @Id
    @Column(length = 100)
    private String id;

    @Column(name = "active")
    private boolean active;

    @Column(name = "name")
    private String name;

    @Column(name = "profile_img")
    private String profileImg;

    @Column(name = "refresh_token")
    private String refreshToken;

    @Column(name = "reg_dt")
    private String regDt;

    @Column(name = "role")
    private String role;

    @Column(name = "user_uuid")
    private String userUuid;

    public void saveRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public void deleteRefreshToken() {
        this.refreshToken = null;
    }

}
