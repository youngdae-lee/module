package com.bubaum.module.Config;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.bubaum.module.Model.Users;
import com.bubaum.module.Rep.UserRepository;

import lombok.RequiredArgsConstructor;


@Service
@RequiredArgsConstructor
public class CustomDetailsService implements UserDetailsService{
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    @Override
    public Users loadUserByUsername(String username) throws UsernameNotFoundException {
    
        return userRepository.findById(username)
        .map(this::createUserDetails)
        .orElseThrow(() -> new UsernameNotFoundException("해당하는 유저를 찾을 수 없습니다."));

    }
    
    private Users createUserDetails(Users user){
   
        return Users.builder()
                .idx(user.getIdx())
                .id(user.getId())
                .pwd(passwordEncoder.encode(user.getPassword()))
                .roles(user.getRoles())
                .build();


    }
}
