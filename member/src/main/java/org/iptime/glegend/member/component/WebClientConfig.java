package org.iptime.glegend.member.component;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.SSLException;

@Configuration
public class WebClientConfig {

    @Bean
    public WebClient createWebClient() throws SSLException {

//		TcpClient tcpClient = TcpClient.create()
//                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 50000) // Connection Timeout
//                .doOnConnected(connection ->
//                        connection.addHandlerLast(new ReadTimeoutHandler(30)) // Read Timeout
//                                  .addHandlerLast(new WriteTimeoutHandler(30))); // Write Timeout
//
//		SslContext sslContext = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build();
//	    HttpClient httpClient = HttpClient.from(tcpClient);
//	    httpClient.secure(builder -> builder.sslContext(sslContext));

        SslContext sslContext = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build();
        HttpClient httpClient = HttpClient.create().secure(builder -> builder.sslContext(sslContext));

        ClientHttpConnector httpConnector = new ReactorClientHttpConnector(httpClient);
        return WebClient.builder().clientConnector(httpConnector).build();
    }
}

