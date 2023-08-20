package com.example.sstest.controller.reponse;

import com.example.sstest.controller.data.Data;
import lombok.*;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class ResponseDTO {

    private String status;
    private String message;
    private Data data;
    
}