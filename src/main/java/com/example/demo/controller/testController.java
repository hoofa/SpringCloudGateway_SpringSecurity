package com.example.demo.controller;

import lombok.var;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

@Controller
public class testController {
    @RequestMapping(value = "/login")
    public String Login(WebSession session, ServerHttpRequest request, final Model model) {
        var param=request.getURI().getQuery();
        if(null!=param){
            if(param.equals("logout")){
                session.getAttributes().clear();
            }else if (param.equals("error")){
                String errorMessage = session.getAttribute("error");
                model.addAttribute("errorMessage", errorMessage);
            }
        }
        return "login";
    }

    @RequestMapping(value = "/test")
    @ResponseBody
    public String test() {
       return "test";
    }

    @RequestMapping(value = "/admin")
    @PreAuthorize("hasAuthority('admin')")
    @ResponseBody
    public Mono<String> admin() {
        return Mono.just("admin");
    }
}
