package org.iptime.glegend.member.controller;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import lombok.extern.log4j.Log4j2;
import org.iptime.glegend.common.model.Result;
import org.iptime.glegend.member.config.SwaggerConfig;
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
import springfox.documentation.annotations.ApiIgnore;

@Log4j2
@RestController
@RequestMapping("/v1")
public class AuthController {

    @Autowired
    private AuthService authService;

    @ApiOperation(value="토큰 발급 ", notes="최초 토큰을 발급 한다.")
    @ApiResponses({
            @ApiResponse(code=200, response= Result.class, message = "토큰 발급 결과 "),
    })
    @PostMapping("/auth")
    public Mono<Object> auth(
            @ApiIgnore ServerHttpRequest request,
            @ApiIgnore ServerHttpResponse response,
            @RequestBody Auth ar
    )
    {
        log.debug("parameter1(AuthRequest) = {}", ar);
        return authService.authClient(request, response, ar);
    }

    @ApiOperation(value="토큰 갱신 ", notes="토큰을 갱신 한다.", authorizations = { @Authorization("asdfasdf") })
    @ApiResponses({
            @ApiResponse(code=200, response= Result.class, message = "토큰 발급 결과 "),
    })
    @PutMapping("/auth")
    @PreAuthorize("hasRole('admin') OR hasRole('auth')")
    public Mono<Object> refresh(
            @AuthenticationPrincipal String cliId,
            @ApiIgnore ServerWebExchange swe,
            @ApiIgnore ServerHttpRequest request
    )
    {
        log.debug("refresh call");
        return authService.refreshCli(cliId, swe, request);
    }

}
