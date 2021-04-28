package org.iptime.glegend.member.controller;

import lombok.extern.log4j.Log4j2;
import org.iptime.glegend.member.model.Auth;
import org.iptime.glegend.member.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Log4j2
@RestController
@RequestMapping("/v1")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/auth/{randomNum}")
    public Mono<Object> auth(
            ServerHttpRequest request,
            ServerHttpResponse response,
            @PathVariable("randomNum") String randomNum,
            @RequestBody Auth ar
    )
    {
        log.debug("parameter1(AuthRequest) = {}", ar);
        return authService.authClient(request, response, randomNum, ar);
    }

    @PutMapping("/auth")
    @PreAuthorize("hasRole('admin') OR hasRole('auth')")
    public Mono<Object> refresh(
            @AuthenticationPrincipal String cliId,
            ServerWebExchange swe,
            ServerHttpRequest request
    )
    {
        log.debug("refresh call");
        return authService.refreshCli(cliId, swe, request);
    }

}
