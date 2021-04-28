package org.iptime.glegend.member.component;

import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Log4j2
@Component
public class SecurityContextRepository implements ServerSecurityContextRepository {

    @Autowired
    private AuthManager authenticationManager;

    @Override
    public Mono<Void> save(ServerWebExchange swe, SecurityContext sc) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /* (non-Javadoc)
     * Bearer 삭제 및 인증체크 및 결과 리턴
     * @see org.springframework.security.web.server.context.ServerSecurityContextRepository#load(org.springframework.web.server.ServerWebExchange)
     */
    @Override
    public Mono<SecurityContext> load(ServerWebExchange swe) {
        ServerHttpRequest request = swe.getRequest();
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader != null) {
            if (authHeader.startsWith("Bearer ")) {
                String authToken = authHeader.substring(7);
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(authToken, authToken);
                auth.setDetails(swe);

                return this.authenticationManager.authenticate(auth).map((authentication) -> new SecurityContextImpl(authentication));
            } else {
                log.warn("Bearer is none.");
                return Mono.empty();
            }
        } else {
            return Mono.empty();
        }
    }

}
