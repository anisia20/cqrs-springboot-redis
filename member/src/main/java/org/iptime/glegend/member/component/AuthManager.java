package org.iptime.glegend.member.component;

import java.sql.Time;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.iptime.glegend.common.command.JwtCmd;
import org.iptime.glegend.common.constants.RedisConstants;
import org.iptime.glegend.common.model.redis.ClientDto;
import org.iptime.glegend.common.util.TimeG;
import org.iptime.glegend.utils.Util;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import lombok.extern.log4j.Log4j2;
import reactor.core.publisher.Mono;

import org.iptime.glegend.common.components.CommonResourceManager;

@Log4j2
@Component
public class AuthManager implements ReactiveAuthenticationManager {
    @Autowired
    private JwtCmd jwtCmd;

    @Autowired
    private CommonResourceManager resourceManager;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {

        String authToken = (String) authentication.getCredentials();

        String secretKey = "";
        String subject = null;
        ServerHttpRequest request = null;
        ServerHttpResponse response = null;
        String uri = null;
        ServerWebExchange swe = null;
        try {
            swe = (ServerWebExchange) authentication.getDetails();
            request = (ServerHttpRequest) swe.getRequest();
            response = (ServerHttpResponse) swe.getResponse();

            if (authToken == null) {
                log.debug("authToken is null");
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return Mono.empty();
            }

            uri = request.getURI().getPath();
            if (uri == null) {
                log.debug("uri is none");
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return Mono.empty();
            }

            Claims payload = jwtCmd.getPayload(authToken);
            log.debug("payload={} uri={}",  payload, uri);
            if (payload == null) {
                log.debug("payload is null, uri={}, token={}, {}", uri, authToken, request.getId());
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return Mono.empty();
            }

            if (uri.startsWith("/v1/auth")) {
                subject = payload.getSubject();
                swe.getAttributes().put("id", subject);
                //TODO key 정의 해야함
                secretKey = "glegend";
            }
            else {
                log.debug("uri is unknown. uri={}", uri);
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return Mono.empty();
            }

        } catch (Exception e) {
            log.error("err={}", e.getMessage(),e);
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return Mono.empty();
        }

        // expired check
        if (subject == null || jwtCmd.validateToken(secretKey, authToken)==false) {
            log.debug("expired token. C={}", subject);
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return Mono.empty();
        }
        Claims claims = jwtCmd.getAllClaimsFromToken(authToken);
        swe.getAttributes().put("claims", claims);
        log.debug("token pass. C={}, exp={}s", subject, (claims.getExpiration().getTime()-System.currentTimeMillis())/1000);

        List<String> rolesMap = null;
        if (uri.startsWith("/v1/auth")) {
            ClientDto dto = (ClientDto) resourceManager.getRedisCmd().hget(RedisConstants.CQRS_H_CLIENT.key, subject);
            if(dto == null) {
                log.error("id is none C={}", subject);
                response.setStatusCode(HttpStatus.NON_AUTHORITATIVE_INFORMATION);
                return Mono.empty();
            }
            dto.setUpdatdt(TimeG.toFormat14());
            resourceManager.getRedisCmd().hput(RedisConstants.CQRS_H_CLIENT.key, subject, dto);
            log.debug("id pass. id={}", dto.getId());

            // role read and save
            try {
                rolesMap = Arrays.asList( claims.get("accessUrl").toString().split(",") );
                log.debug("accessUrl={}, rolesMap={}", claims.get("accessUrl"), rolesMap);
            } catch(Exception e) {
                log.warn("accessUrl is unknown. C={}, accessUrl={}, err={}", subject, claims.get("accessUrl"), e.getMessage());
                response.setStatusCode(HttpStatus.NON_AUTHORITATIVE_INFORMATION);
                return Mono.empty();
            }
        }
        else {
            rolesMap = new ArrayList<String>();
        }

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                subject,
                null,
                rolesMap.stream().map(authority -> new SimpleGrantedAuthority("ROLE_"+authority)).collect(Collectors.toList())
        );

        auth.setDetails(claims);

        return Mono.just(auth);
    }
}
