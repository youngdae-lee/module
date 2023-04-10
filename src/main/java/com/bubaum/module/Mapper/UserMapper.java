package com.bubaum.module.Mapper;

import java.math.BigInteger;

import org.apache.ibatis.annotations.Mapper;
import org.springframework.web.bind.annotation.RequestParam;

import com.bubaum.module.Dto.UserDto;
import com.bubaum.module.Model.Users;

import io.lettuce.core.dynamic.annotation.Param;

@Mapper
public interface UserMapper {
    public Users userInfo(@Param("userid") String userid);
}
