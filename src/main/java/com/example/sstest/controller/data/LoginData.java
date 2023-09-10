package com.example.sstest.controller.data;

import lombok.*;

@Getter
@Builder
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class LoginData implements Data {

    private Integer memberId;

    private String name;

    private String statusMessage;

    private String accessToken;

}