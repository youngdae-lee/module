package com.bubaum.module.Controller;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.convert.RedisTypeMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.bubaum.module.Config.JwtFilter;
import com.bubaum.module.Config.JwtProvider;
import com.bubaum.module.Dto.LoginDto;
import com.bubaum.module.Dto.UserDto;
import com.bubaum.module.Model.Message;
import com.bubaum.module.Model.Token;
import com.bubaum.module.Model.Users;
import com.bubaum.module.ServiceImpl.Service.UserService;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import springfox.documentation.annotations.ApiIgnore;
import springfox.documentation.service.LoginEndpoint;

@RequiredArgsConstructor
@RestController
@RequestMapping("/v1/user")
@Api(tags = {"유저 API"})
public class UserController {
    @Autowired
    UserService userService;
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    private final JwtProvider jwtProvider;
   
    @PostMapping("/refresh")
    public ResponseEntity<Message> refresh(HttpServletRequest request) {
        //1. Request Header 에서 JWT Token 추출
        String token = jwtProvider.resolveToken(request);
        if(jwtProvider.validateToken(token)!=null){
            // 액세스토큰이 만료된 상황이 아닌데 refresh를 요청한 상황
            Long expriation =jwtProvider.getExpiration(token);
            redisTemplate.opsForValue().set(token,"delete",expriation,TimeUnit.MILLISECONDS);

        }
     
        Authentication authentication=jwtProvider.getAuthentication(token);
        
        return jwtProvider.createAccessToken(authentication);

    }
    @PostMapping("/logout")
    public ResponseEntity<Message> logout(HttpServletRequest request){
        String token = jwtProvider.resolveToken(request);
        Long expriation =jwtProvider.getExpiration(token);
        redisTemplate.opsForValue().set(token,"logout",expriation,TimeUnit.MILLISECONDS);
        Message msg = new Message();
        msg.setStatus(0);
        msg.setMessage("로그아웃 성공");
        msg.setResult("로그아웃이 성공하였습니다.");
        return ResponseEntity.status(HttpStatus.OK).body(msg);

    }

    
    
    @PostMapping("/test")
    public String test(Authentication authentication) throws Exception {
    
        Users user = (Users) authentication.getPrincipal();
        System.out.println(user);
        System.out.println(user.getUsername());

        // UserDto userDto =userService.userInfo(user.getUsername());
        // System.out.println(userDto);
        return "test";
    }

    @PostMapping("/login")
    @ApiOperation(value = "바움 모듈 로그인", notes = "바움 모듈에 로그인을 한다.")
    @ApiResponses({
        @ApiResponse(code = 200, message = "성공입니다.")
        , @ApiResponse(code = 500, message = "서버에 문제가 발생하였습니다.")
    })
  
    public ResponseEntity<Message> login( @RequestBody LoginDto loginDto) throws Exception {
        String memberId = loginDto.getId();
        String password = loginDto.getPwd();
        Token tokenInfo = userService.login(memberId, password);
        Message msg = new Message();
        msg.setStatus(0);
        msg.setMessage("로그인 성공");
        msg.setResult(tokenInfo);
        return ResponseEntity.status(HttpStatus.OK).body(msg);
    }

    

    
}
