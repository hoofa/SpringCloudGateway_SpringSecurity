package com.example.demo.common.auth.formlogin;

import java.net.URI;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

public class AuthFailureHandler implements ServerAuthenticationFailureHandler {
    private final URI location;
    private ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

    public AuthFailureHandler(String location) {
        Assert.notNull(location, "location cannot be null");
        this.location = URI.create(location);
    }

    public void setRedirectStrategy(ServerRedirectStrategy redirectStrategy) {
        Assert.notNull(redirectStrategy, "redirectStrategy cannot be null");
        this.redirectStrategy = redirectStrategy;
    }

    public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException exception) {
        webFilterExchange.getExchange().getSession().subscribe(session->{
            try{
                session.getAttributes().put("error", exception.getMessage());
            }catch (Exception e){

            }

        });
        return this.redirectStrategy.sendRedirect(webFilterExchange.getExchange(), this.location);
    }
}


