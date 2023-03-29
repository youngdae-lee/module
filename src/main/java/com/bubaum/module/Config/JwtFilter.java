package com.bubaum.module.Config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;
import lombok.RequiredArgsConstructor;
@RequiredArgsConstructor
public class JwtFilter extends GenericFilterBean{
    private final JwtProvider JwtProvider;
    private final RedisTemplate<String,Object> redisTemplate;
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
                String token = JwtProvider.resolveToken((HttpServletRequest) request);
 
                // 2. validateToken 으로 토큰 유효성 검사
                if (token != null && JwtProvider.validateToken(token)!=null) {
                    String isLogout = (String)redisTemplate.opsForValue().get(token);
                    if(ObjectUtils.isEmpty(isLogout)){
                         // 토큰이 유효할 경우 토큰에서 Authentication 객체를 가지고 와서 SecurityContext 에 저장
                        if (!((HttpServletRequest) request).getRequestURI().equals("/v1/user/reissue")) {
                            Authentication authentication = JwtProvider.getAuthentication(token);
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                        }
                    }
                   
                }
                chain.doFilter(request, response);
    }

    
    

}
