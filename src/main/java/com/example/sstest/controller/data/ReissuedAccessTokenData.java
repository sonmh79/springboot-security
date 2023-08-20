package com.example.sstest.controller.data;

import lombok.*;

@Getter
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ReissuedAccessTokenData implements Data {

    private String accessToken;

}