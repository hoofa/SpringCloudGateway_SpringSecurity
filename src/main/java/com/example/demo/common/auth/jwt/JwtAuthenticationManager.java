package com.example.demo.common.auth.jwt;

import lombok.AllArgsConstructor;
import lombok.var;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Component
@AllArgsConstructor
public class JwtAuthenticationManager  implements ReactiveAuthenticationManager {
    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        List<String> rolesMap = new ArrayList<String>();
        rolesMap.add("admin");
        var u= new UsernamePasswordAuthenticationToken(
                "admin",
                null,
                rolesMap.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
        );
        return Mono.just(u);
    }
}
