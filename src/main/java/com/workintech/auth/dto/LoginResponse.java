package com.workintech.auth.dto;

import com.workintech.auth.entity.Member;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {
    private Member member;
    private String jwt;
}
