package com.bubaum.module.Model;

import javax.persistence.Id;

import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class Token {
    

    private String grantType;
    private String accessToken;
    private String refreshToken;
}
