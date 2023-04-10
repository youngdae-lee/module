package com.bubaum.module.Config;

import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.bubaum.module.Mapper.UserMapper;
import com.bubaum.module.Model.Message;
import com.bubaum.module.Model.Token;
import com.bubaum.module.Model.Users;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Component
public class JwtProvider {
    private final Key key;
    @Autowired
    private RedisTemplate<String,Object> redisTemplate;
    @Autowired
    private UserMapper userMapper;
    public JwtProvider(@Value("${jwt.secretKey}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }
 
    // 유저 정보를 가지고 AccessToken, RefreshToken 을 생성하는 메서드
    public Token generateToken(Authentication authentication) {
        // 권한 가져오기
        Users user = (Users)authentication.getPrincipal();
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
 
        long now = (new Date()).getTime();
        // Access Token 생성
        Date accessTokenExpiresIn = new Date(now + 180);
     
        String accessToken = Jwts.builder()
                .setSubject(user.getId())
                .claim("auth", authorities)
                .setExpiration(accessTokenExpiresIn)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
 
        // Refresh Token 생성
        String refreshToken = Jwts.builder()
                .setExpiration(new Date(now + 86400000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
        redisTemplate.opsForValue().set(user.getId(), refreshToken, 86300000,TimeUnit.MILLISECONDS);

        return Token.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
 
    // JWT 토큰을 복호화하여 토큰에 들어있는 정보를 꺼내는 메서드
    public Authentication getAuthentication(String accessToken) {
        // 토큰 복호화
        Claims claims = parseClaims(accessToken);
 
        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }
 
        // 클레임에서 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
        
        List<String> roles = new ArrayList<String>();
        for(GrantedAuthority auth:authorities){
            roles.add(auth.getAuthority());
        }
        // Users 객체를 만들어서 Authentication 리턴
        Users principal =userMapper.userInfo(claims.getSubject());
        principal.setRoles(roles);        
        //  UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }
 
    // 토큰 정보를 검증하는 메서드
    public Claims validateToken(String token) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e);
            throw new JwtException("유효하지 않은 jwt 토큰");
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e);
            throw new JwtException("유효하지 않은 jwt 토큰");
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e);
            throw new JwtException("유효하지 않은 jwt 토큰");
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e);
            throw new JwtException("유효하지 않은 jwt 토큰");
        }
    }
 
    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }


    public String resolveToken(HttpServletRequest request) {

        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public ResponseEntity<Message> createAccessToken(Authentication authentication) {
        return createToken(authentication);
    }

    public ResponseEntity<Message> createToken(Authentication authentication) {
        String userId = authentication.getName();
        String refreshToken = (String)redisTemplate.opsForValue().get(userId);
        Message msg = new Message();
        
        if(refreshToken!=null){

            String authorities = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(","));
            long now = (new Date()).getTime();
            Date accessTokenExpiresIn = new Date(now + 180);
    
            String accesstoken = Jwts.builder()
                    .setSubject(authentication.getName())
                    .claim("auth",authorities) // 정보
                    .setExpiration(accessTokenExpiresIn) // 토큰 만료 시간
                    .signWith(key, SignatureAlgorithm.HS256)
                    .compact();
            Token token =Token.builder()
            .grantType("Bearer")
            .accessToken(accesstoken)
            .refreshToken(refreshToken)
            .build();

            msg.setStatus(0);
            msg.setMessage("액세스 토큰 발급성공");
            msg.setResult(token);
            return ResponseEntity.status(HttpStatus.OK).body(msg);
        }else{

            msg.setStatus(1);
            msg.setMessage("리프레시 토큰이 만료되었습니다.");
            msg.setResult("");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(msg);

        }

    }

    // accessToken의 남은 유효기간 얻기
    public Long getExpiration(String accessToken){

    Date expiration = Jwts.parserBuilder().setSigningKey(key)
        .build().parseClaimsJws(accessToken).getBody().getExpiration();

    //현재 시간
    long now = new Date().getTime();

    return (expiration.getTime() - now);

    }
}
