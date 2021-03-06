package org.iptime.glegend.member.service;

import io.jsonwebtoken.Claims;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import org.iptime.glegend.common.code.ResultCode;
import org.iptime.glegend.common.command.JwtCmd;
import org.iptime.glegend.common.constants.RedisConstants;
import org.iptime.glegend.common.model.Result;
import org.iptime.glegend.common.model.redis.ClientDto;
import org.iptime.glegend.config.redis.command.RedisCmd;
import org.iptime.glegend.member.component.AuthManager;
import org.iptime.glegend.member.model.Auth;
import org.iptime.glegend.member.model.AuthResult;
import org.iptime.glegend.utils.ADMSHA512Hash;
import org.iptime.glegend.utils.Util;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.iptime.glegend.common.components.CommonResourceManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetAddress;

@Data
@Service
@Log4j2
public class AuthService {

    @Autowired
    RedisCmd redisCmd;

    @Autowired
    JwtCmd jwtCmd;

    @Autowired
    CommonResourceManager commonResourceManager;

    @Autowired
    AuthManager authenticationManager;

    private String name=AuthService.class.getSimpleName();

    public Mono<Object> authClient(ServerHttpRequest request, ServerHttpResponse response, Auth ar) {
        Result result = new Result();
        String ip = Util.getRemoteIpAddr(request);

        log.debug("auth token params(Auth)={}, ip={}", ar, ip);

        // validation ??????
        if (Util.isValid(ar, result) == false) {
            log.warn("validation check faild. C=[{}] err=[{}/{}]",
                    ar.getId(), result.getResult(), result.getResultDescription());

            response.setStatusCode(HttpStatus.BAD_REQUEST);
            return Mono.just(result);
        }

        // ID, PWD ??????
        //TODO ???????????? ???????????? ???
        ClientDto tmp = new ClientDto();
        tmp.setId(ar.getId());
        tmp.setPwd(ADMSHA512Hash.getDigest(ar.getPwd()));
        redisCmd.hput(RedisConstants.CQRS_H_CLIENT.key, ar.getId(), tmp);
        //

        ClientDto clientDetails = (ClientDto) redisCmd.hget(RedisConstants.CQRS_H_CLIENT.key, ar.getId());
        if (clientDetails == null) {
            log.debug("cannot found cliId. C={}, ip={}", ar.getId());
            result.setResultFail(ResultCode.R_100.r, ResultCode.R_100.rd+"_C_"+ar.getId());
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return Mono.just(result);
        }

        // token ??????
        String token = jwtCmd.getToken( clientDetails.getId(),"order,member", false );
        if ("".contentEquals(token)) {
            result.setResultFail(ResultCode.R_100.r, ResultCode.R_100.rd+"_token");
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return Mono.just(result);
        }

        /////////////////////////

        String refresh_token = jwtCmd.getToken(
                clientDetails.getId(),"auth", true);
        if ("".contentEquals(refresh_token)) {
            result.setResultFail(ResultCode.R_100.r, ResultCode.R_100.rd+"_refreshtoken");
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return Mono.just(result);
        }

        result.put(AuthResult.FIELD_TOKEN, token);
        result.put(AuthResult.FIELD_REFRESH_TOKEN, refresh_token);

        result.setSuccess();
        log.debug("auth token C={}, ip={}, result={}", ar.getId(), ip, result);

        return Mono.just(result);
    }

    public Mono<Object> refreshCli(@AuthenticationPrincipal String id, ServerWebExchange swe,
                                   ServerHttpRequest request) {

        Result result = new Result();

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // Bearer ??????
        if (authHeader == null || authHeader.startsWith("Bearer ") == false)
            return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());

        String authToken = authHeader.substring(7);
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(authToken, authToken);
        auth.setDetails(swe);

        // token ?????? ??? ??????
        return this.authenticationManager.authenticate(auth).flatMap((authentication) -> {
            Claims claims = (Claims) authentication.getDetails();
            String subject = (String) authentication.getPrincipal();

            log.debug("auth token refresh claims = {}", claims);

            // token ??????
            String token = jwtCmd.getToken(subject, "order,member", false);
            if (StringUtils.hasText(token) == false) {
                log.warn("token generate error. C={}", subject);
                return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
            }

            result.put(AuthResult.FIELD_TOKEN, token);
            result.setSuccess();

            log.debug("auth token refresh result = [{}]", result);
            return Mono.just(result);

        });
    }

    public static String myIp () {
        String ipStr = "";
        InetAddress ip;
        try {
            ip = InetAddress.getLocalHost();
            ipStr = ip.getHostName();
            System.out.println("Host Name = [" + ip.getHostName() + "]");
            System.out.println("Host Address = [" + ip.getHostAddress() + "]");
        }
        catch (Exception e) {
            System.out.println(e);
        }
        return ipStr;
    }

}
