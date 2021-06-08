package com.example.demo.common.auth.jwt;


import lombok.var;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

public class JwtFilter implements WebFilter {
    private final ServerSecurityContextRepository repository;

    public JwtFilter(ServerSecurityContextRepository repository) {
        Assert.notNull(repository, "repository cannot be null");
        this.repository = repository;
    }

    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return  this.repository.load(exchange)
                .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
                .flatMap(o->{
                    return chain.filter(exchange).subscriberContext((c) -> {
                        return c.hasKey(SecurityContext.class) ? c : this.withSecurityContext(c, exchange);
                });
        });
    }

    private Context withSecurityContext(Context mainContext, ServerWebExchange exchange) {
        return mainContext.putAll((Context)this.repository.load(exchange).as(ReactiveSecurityContextHolder::withSecurityContext));
    }
}
