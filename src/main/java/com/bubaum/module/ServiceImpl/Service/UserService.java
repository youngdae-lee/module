package com.bubaum.module.ServiceImpl.Service;

import com.bubaum.module.Model.Token;

public interface UserService {
    
    Token login(String id, String pwd) throws Exception;
}
