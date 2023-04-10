package com.bubaum.module.ServiceImpl.Service;

import java.math.BigInteger;

import com.bubaum.module.Dto.UserDto;
import com.bubaum.module.Model.Token;
import com.bubaum.module.Model.Users;

public interface UserService {
    
    Token login(String id, String pwd) throws Exception;
    Users userInfo(String userid) throws Exception;
}
