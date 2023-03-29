package com.bubaum.module.Model;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinTable;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;



@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description ="유저")
@Entity(name="USERS")
public class Users implements UserDetails{

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Schema(description = "유저 IDX", nullable = false, example = "1")
    private Long idx;
    @Schema(description = "유저 아이디", nullable = false, example = "test")
    private String id;
    @Schema(description = "유저 비밀번호", nullable = false, example = "1234")
    private String pwd;
 


    
    @ElementCollection
    @Builder.Default
    @JoinTable(name = "USERS_ROLES")
    @Schema(description = "유저권한", example = "USER or ADMIN")
    private List<String> roles = new ArrayList<>();

    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream()
        .map(SimpleGrantedAuthority::new)
        .collect(Collectors.toList());
    }
    
    @Override
    public String getUsername() {
        return id;
    }

    @Override
    public String getPassword() {
        // TODO Auto-generated method stub
        return pwd;
       
    }


    @Override
    public boolean isAccountNonExpired() {
        // TODO Auto-generated method stub
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        // TODO Auto-generated method stub
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // TODO Auto-generated method stub
        return true;
    }

    @Override
    public boolean isEnabled() {
        // TODO Auto-generated method stub
        return true;
    }
    
}
