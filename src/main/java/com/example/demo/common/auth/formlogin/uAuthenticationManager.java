package com.example.demo.common.auth.formlogin;

import lombok.var;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import reactor.core.publisher.Mono;

import com.bim999.iotpre.dao.domain.User;


public class uAuthenticationManager implements ReactiveAuthenticationManager {
    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        var user = authentication.getPrincipal().toString();
        var pass=authentication.getCredentials().toString();
        // 如果数据库中未查到该账号:
        if (!user.equals("admin")) {
            throw new UsernameNotFoundException("该用户不存在");
        } else {
            if (!pass.equals("123")) {
                throw new BadCredentialsException("密码不正确");
            }
        }
        var u=new User();
        u.name=user;
        u.role="admin";
        var userDetails = new UserPrincipal(u);
        return Mono.just(new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()));

    }
}
