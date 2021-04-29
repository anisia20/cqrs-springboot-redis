package org.iptime.glegend.member.config;

import static java.util.concurrent.TimeUnit.MILLISECONDS;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.netty.NettyReactiveWebServerFactory;
import org.springframework.boot.web.reactive.server.ReactiveWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;
import lombok.extern.log4j.Log4j2;

@Configuration
@Profile("!local")
@Log4j2
public class NettyConfig {

    @Value("${server.netty.reader-idle-time:60000}")
    private Duration readerIdleTime;

    @Value("${server.netty.writer-idle-time:60000}")
    private Duration writerIdleTime;

    @Bean
    public ReactiveWebServerFactory reactiveWebServerFactory() {
        final NettyReactiveWebServerFactory factory = new NettyReactiveWebServerFactory();
        factory.addServerCustomizers(server -> server.tcpConfiguration(
                tcp -> tcp.bootstrap(bootstrap -> bootstrap.childHandler(new ChannelInitializer<Channel>() {
                    @Override
                    protected void initChannel(Channel channel) {
                        channel.pipeline().addLast(new IdleStateHandler(readerIdleTime.toMillis(), writerIdleTime.toMillis(), 0, MILLISECONDS),
                                new ChannelDuplexHandler() {
                                    @Override
                                    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) {
                                        if (evt instanceof IdleStateEvent) {
                                            ctx.close();
                                            log.debug("session timeout. close. {}", channel.remoteAddress());
                                        }
                                    }
                                });

                        log.debug("session open. {}", channel.remoteAddress());
                    }
                }))
        ));

        return factory;
    }

}
