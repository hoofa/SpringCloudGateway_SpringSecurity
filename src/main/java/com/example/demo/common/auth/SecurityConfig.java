package com.example.demo.common.auth;

import com.example.demo.common.auth.formlogin.AuthFailureHandler;
import com.example.demo.common.auth.formlogin.uAuthenticationManager;
import com.example.demo.common.auth.jwt.JwtAuthenticationManager;
import com.example.demo.common.auth.jwt.JwtFilter;
import com.example.demo.common.auth.jwt.JwtSecurityContextRepository;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity(order = Ordered.HIGHEST_PRECEDENCE)
@AllArgsConstructor
public class SecurityConfig {

    private JwtAuthenticationManager jwtAuthenticationManager;
    private JwtSecurityContextRepository jwtSecurityContextRepository;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf().disable() //注释就是使用 csrf 功能
                .headers().frameOptions().disable()//解决 in a frame because it set 'X-Frame-Options' to 'DENY' 问题
                .and()
                .authorizeExchange()
                .pathMatchers("/test/**")
                .authenticated()
                .pathMatchers("/**")
                .permitAll()
                .and()

                .exceptionHandling()
                .authenticationEntryPoint((swe, e) ->{
                    if(swe.getRequest().getURI().getPath().startsWith("/test")){
                        return Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED));
                    }else{
                        return new RedirectServerAuthenticationEntryPoint("/login").commence(swe,new AuthenticationCredentialsNotFoundException("Not Authenticated", new AccessDeniedException("Denied"))).then(Mono.empty());
                    }
                })
                .accessDeniedHandler((swe, e) ->
                        Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN))
                ).and()

//                .authenticationManager(jwtAuthenticationManager)
//                .securityContextRepository(jwtSecurityContextRepository)
//                .authorizeExchange()
//                .pathMatchers(HttpMethod.OPTIONS).permitAll()
////                .pathMatchers("/login").permitAll()
//                .anyExchange().authenticated()
//                .and()
//                .addFilterBefore(jwtAuthenticationWebFilter(), SecurityWebFiltersOrder.HTTP_BASIC)

                .formLogin()
                .loginPage("/login")   //登录请求页
                .securityContextRepository(securityContextRepository())
                .authenticationManager(authenticationManager())
                .authenticationFailureHandler(new AuthFailureHandler("/login?error"))
                //.authenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler("/admin"))
                .and()
                .logout()
//                .logoutUrl("/logout")
//                .logoutSuccessHandler(logoutSuccessHandler("/login?logout"))
                .and()
                .addFilterBefore(new JwtFilter(jwtSecurityContextRepository),SecurityWebFiltersOrder.REACTOR_CONTEXT)
//                .addFilterAfter(authenticationWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }



//    @Bean
//    public AuthenticationWebFilter authenticationWebFilter() {
//        AuthenticationWebFilter filter = new AuthenticationWebFilter(authenticationManager());
//        filter.setSecurityContextRepository(securityContextRepository());
////        filter.setAuthenticationConverter(jsonBodyAuthenticationConverter());
////        filter.setAuthenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler("/home"));
////        filter.setAuthenticationFailureHandler( new AuthFailureHandler("/login?error"));
////        filter.setAuthenticationFailureHandler(new ServerAuthenticationEntryPointFailureHandler(new RestServerAuthenticationEntryPoint()));
//        filter.setRequiresAuthenticationMatcher(
//                ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, "/login**")
//        );
//        return filter;
//    }

    @Bean
    public ServerSecurityContextRepository securityContextRepository() {
        WebSessionServerSecurityContextRepository securityContextRepository =
                new WebSessionServerSecurityContextRepository();

//        securityContextRepository.setSpringSecurityContextAttrName("securityContext");

        return securityContextRepository;
    }

    @Bean
    public ReactiveAuthenticationManager authenticationManager() {
        return new uAuthenticationManager();
    }
}