package com.bubaum.module.Dto;

import java.math.BigInteger;

import lombok.Data;

@Data
public class UserDto {
    private BigInteger idx;
    private String id;
    private String pwd;

}
