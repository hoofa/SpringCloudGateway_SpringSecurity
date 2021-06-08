package com.example.demo.common.auth.formlogin;

import com.bim999.iotpre.dao.domain.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.List;

public class UserPrincipal implements UserDetails {
    private User user;
    private boolean enabled = true;
    private String username;
    private String password;

    public UserPrincipal(User user) {
        this.user = user;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() { // 帐户是否过期
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() { // 帐户是否被冻结
        return true;
    }

    // 帐户密码是否过期，一般有的密码要求性高的系统会使用到，比较每隔一段时间就要求用户重置密码
    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    @JsonIgnore
    public String getUsername() {
        return user.username;
    }

    @Override
    @JsonIgnore
    public String getPassword() {
        return user.password;
    }

    @Override
    public boolean isEnabled() {  // 帐号是否可用
        return enabled;
    }


    @Override
    @JsonIgnore
    public List<GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
//        for (Role role : roles) {
        if (null != this.user.role) {
            authorities.add(new SimpleGrantedAuthority(this.user.role.toString()));
        }
//        }
        return authorities;
    }



}
