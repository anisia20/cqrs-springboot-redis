package org.iptime.glegend.member.filter;

import io.jsonwebtoken.Claims;
import lombok.extern.log4j.Log4j2;
import org.iptime.glegend.common.command.JsonCmd;
import org.iptime.glegend.common.util.UuidMaker;
import org.iptime.glegend.utils.Util;
import org.reactivestreams.Publisher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeDecorator;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.io.ByteArrayOutputStream;
import java.nio.channels.Channels;
import java.util.Map;

@Log4j2
@Configuration
public class CommonWebFilter implements WebFilter {

    @Value("${member.debug_log:false}")
    private boolean isTraceDebugLog;

    @Autowired
    JsonCmd jsonCmd;

    @Autowired
    UuidMaker uuidMaker;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        long startTime = System.currentTimeMillis();

        String ip = Util.getRemoteIpAddr(exchange.getRequest());
        String path = exchange.getRequest().getURI().getPath();
        String method = exchange.getRequest().getMethodValue();

        Claims claims = exchange.getAttribute("claims");
        String cliId = "";
        if (claims != null)
            cliId = claims.getSubject();
        else {
            if (path.indexOf("client") > 0) cliId = exchange.getRequest().getQueryParams().getFirst("id");
        }
        if (cliId != null) exchange.getAttributes().put("cliId", cliId);

        String logkey = uuidMaker.nextKey(uuidMaker.TGC);
        exchange.mutate().request(builder -> {
            builder.header("logkey", logkey);
        });

        ServerWebExchange webExchange = exchange;
        if (isTraceDebugLog) {
            if ("GET".equals(method)) {
                log.info("request start. LK={}, id={}, ip={}, url={}, method={}, params={}", logkey, cliId, ip, path, method, exchange.getRequest().getQueryParams());
            }
            webExchange = decorate(exchange, cliId, ip, path, method);

            if ((path != null && (path.indexOf("/v1/auth") >= 0 || path.indexOf("/v1/client/auth") >= 0)) && "PUT".equals(method)) {
                log.info("request start. LK={}, id={}, ip={}, url={}, method={}", logkey, cliId, ip, path, method);
            }
        } else {
            log.info("request start. LK={}, id={}, ip={}, url={}, method={}", logkey, cliId, ip, path, method);
        }

        return chain.filter(webExchange)
                .doAfterTerminate(() -> {
                    log.info("request end. LK={}, id={}, ip={}, url={}, method={}, status={}, r={}, elapsed_time={}",
                            exchange.getRequest().getHeaders().get("logkey"), exchange.getAttributes().get("cliId"),
                            ip, path, method, exchange.getResponse().getStatusCode(), exchange.getAttributes().get("r"),
                            System.currentTimeMillis() - startTime);
                });
    }

    private ServerWebExchange decorate(ServerWebExchange exchange, String cliId, String ip, String path, String method) {
        final ServerHttpRequest reqDecorated = new ServerHttpRequestDecorator(exchange.getRequest()) {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();

            @Override
            public Flux<DataBuffer> getBody() {

                if (Util.isNullOrEmpty(exchange.getRequest().getHeaders().get("Content-Type")) == false) {
                    String cType = exchange.getRequest().getHeaders().get("Content-Type").get(0);
                    if (cType.indexOf("multipart/form-data") >= 0) {
                        log.info("request start. LK={}, id={}, ip={}, url={}, method={}, params={}",
                                exchange.getRequest().getHeaders().get("logkey"), exchange.getAttributes().get("cliId"), ip, path, method, cType);
                        return super.getBody();
                    }
                }

                return super.getBody().map(dataBuffer -> {
                    log.debug("getBody. LK={}, id={}, ip={}, url={}, method={}, readableByteCount={}, capacity={}, readPosition={}, writePosition={}",
                            exchange.getRequest().getHeaders().get("logkey"), cliId, ip, path, method, dataBuffer.readableByteCount(), dataBuffer.capacity(), dataBuffer.readPosition(), dataBuffer.writePosition());

                    //XXX if (dataBuffer.capacity() < getHeaders().getContentLength()) return dataBuffer;

                    String jsonStr = readBuffer(baos, dataBuffer);
                    if (jsonStr != null) {
                        Map<String,String> paramMap = jsonCmd.stringToHashmap(jsonStr);
                        if (paramMap != null && paramMap.get("sm_id") != null) {
                            exchange.getAttributes().put("cliId", paramMap.get("sm_id"));
                        }

                        if (jsonStr.length() >= 1000)
                            log.info("request start. LK={}, id={}, ip={}, url={}, method={}, paramLen={}(1000b over)",
                                    exchange.getRequest().getHeaders().get("logkey"), exchange.getAttributes().get("cliId"), ip, path, method, jsonStr.length());
                        else if (paramMap == null)
                            log.info("request start. LK={}, id={}, ip={}, url={}, method={}, paramStr={}",
                                    exchange.getRequest().getHeaders().get("logkey"), cliId, ip, path, method, jsonStr);
                        else
                            log.info("request start. LK={}, id={}, ip={}, url={}, method={}, paramMap={}",
                                    exchange.getRequest().getHeaders().get("logkey"), exchange.getAttributes().get("cliId"), ip, path, method, paramMap);
                    }
                    else if (dataBuffer.readableByteCount() <= 0){
                        log.info("request start. LK={}, id={}, ip={}, url={}, method={}, paramLen={}",
                                exchange.getRequest().getHeaders().get("logkey"), cliId, ip, path, method, baos.toByteArray().length);
                    }
                    return dataBuffer;
                });

            }
        };

        final ServerHttpResponse resDecorated = new ServerHttpResponseDecorator(exchange.getResponse()) {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();

            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                return super.writeWith(Flux.from(body).map(buffer -> {
                    String jsonStr = readBuffer(baos, buffer);

                    if (jsonStr != null) {
                        exchange.getAttributes().put("r", jsonStr);
                        log.info("response body. LK={}, id={}, ip={}, url={}, method={}, status={}, r={}",
                                exchange.getRequest().getHeaders().get("logkey"), exchange.getAttributes().get("cliId"),
                                ip, path, method, exchange.getResponse().getStatusCode(), jsonStr);
                    }
                    else if (buffer.readableByteCount() <= 0){
                        log.info("response body. LK={}, id={}, ip={}, url={}, method={}, status={}",
                                exchange.getRequest().getHeaders().get("logkey"), exchange.getAttributes().get("cliId"),
                                ip, path, method, exchange.getResponse().getStatusCode());
                    }
                    return buffer;
                }));
            }

            @Override
            public Mono<Void> writeAndFlushWith(Publisher<? extends Publisher<? extends DataBuffer>> body) {
                return super.writeAndFlushWith(Flux.from(body).map(publisher -> Flux.from(publisher).map(buffer -> {
                    String jsonStr = readBuffer(baos, buffer);
                    if (jsonStr != null) {
                        exchange.getAttributes().put("r", jsonStr);
                        log.info("response body. LK={}, id={}, ip={}, url={}, method={}, status={}, r={}",
                                exchange.getRequest().getHeaders().get("logkey"), exchange.getAttributes().get("cliId"),
                                ip, path, method, exchange.getResponse().getStatusCode(), jsonStr);
                    }
                    else if (buffer.readableByteCount() <= 0){
                        log.info("response body. LK={}, id={}, ip={}, url={}, method={}, status={}",
                                exchange.getRequest().getHeaders().get("logkey"), exchange.getAttributes().get("cliId"),
                                ip, path, method, exchange.getResponse().getStatusCode());
                    }
                    return buffer;
                })));
            }
        };

        return new ServerWebExchangeDecorator(exchange) {

            @Override
            public ServerHttpRequest getRequest() {
                return reqDecorated;
            }

            @Override
            public ServerHttpResponse getResponse() {
                return resDecorated;
            }
        };
    }

    private String readBuffer(ByteArrayOutputStream baos, DataBuffer buffer) {
        try {
            Channels.newChannel(baos).write(buffer.asByteBuffer().asReadOnlyBuffer());

            String jsonStr = new String(baos.toByteArray(), "UTF-8");
            if (jsonCmd.isJSONValid(jsonStr))
                return jsonStr;
            else
                return null;
        } catch (Exception e) {
            return null;
        }
    }

}

