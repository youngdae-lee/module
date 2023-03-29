package com.bubaum.module.Dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class LoginDto {
    @Schema(description = "유저 아이디", nullable = false, example = "test")
    private String id;
    @Schema(description = "유저 비밀번호", nullable = false, example = "1234")
    private String pwd;
}
