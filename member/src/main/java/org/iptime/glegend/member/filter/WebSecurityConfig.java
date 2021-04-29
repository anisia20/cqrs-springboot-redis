package org.iptime.glegend.member.filter;

import org.iptime.glegend.member.component.AuthManager;
import org.iptime.glegend.member.component.SecurityContextRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class WebSecurityConfig {

    @Autowired
    private AuthManager authenticationManager;

    @Autowired
    private SecurityContextRepository securityContextRepository;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .exceptionHandling()
                .authenticationEntryPoint((swe, e) -> {
                    return Mono.fromRunnable(() -> {
                        swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    });
                }).accessDeniedHandler((swe, e) -> {
                    return Mono.fromRunnable(() -> {
                        swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    });
                }).and()
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .authenticationManager(authenticationManager)
                .securityContextRepository(securityContextRepository)
                .authorizeExchange()
                // 상위 권한 우선
//				.pathMatchers(HttpMethod.PUT, "/v1/client/auth").hasRole("auth")
                .pathMatchers("/documentation/**").permitAll() // 산출물 경로
                .pathMatchers("/swagger-ui/**").permitAll() // 산출물 경로
                .pathMatchers("favicon.ico").permitAll() // 산출물 경로
                .pathMatchers("/swagger-resources/**").permitAll() // 산출물 경로
                .pathMatchers("/v2/api-docs").permitAll() // 산출물 경로
                .pathMatchers("/webjars/**").permitAll() // 산출물 경로
                .pathMatchers("/v1/auth/**").permitAll()
                .pathMatchers("/ext/**").permitAll() // 산출물 경로
                .anyExchange().authenticated()
                .and().build();
    }

    @Bean
    public RouterFunction<ServerResponse> imgRouter() {
        return RouterFunctions.resources("/ext/**", new ClassPathResource("ext/"));
    }

}
