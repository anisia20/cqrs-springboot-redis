package org.iptime.glegend.member;

import java.net.InetAddress;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

import org.iptime.glegend.common.command.JsonCmd;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.ComponentScans;
import org.springframework.core.env.AbstractEnvironment;

import lombok.extern.log4j.Log4j2;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.reactive.config.EnableWebFlux;

@SpringBootApplication
@EnableScheduling
@Log4j2
@ComponentScans(value = {
        @ComponentScan("org.iptime.glegend"),
})
@EnableWebFlux
public class MemberApplication {

    @Autowired
    JsonCmd jsonCmd;

    static String ACCESS_LOG_ENABLED = "reactor.netty.http.server.accessLogEnabled";
    public static void main(String[] args) {
        if (System.getProperty(AbstractEnvironment.ACTIVE_PROFILES_PROPERTY_NAME) == null) {
            System.setProperty(AbstractEnvironment.ACTIVE_PROFILES_PROPERTY_NAME, "local");
        }

        if (System.getProperty(ACCESS_LOG_ENABLED) == null) {
            System.setProperty(ACCESS_LOG_ENABLED, "true");
        }

        SpringApplication.run(MemberApplication.class, args);
    }

    @PostConstruct
    public void onStartup() {
        log.info("################ System-up start ################");
        try {
            InetAddress ip = InetAddress.getLocalHost();
            String hostname = ip.getHostName();
            jsonCmd.initObjectMapper();

        } catch (Exception e) {
            log.error("", e);
        }
        log.info("################ System-up complete ################");
    }

    @PreDestroy
    public void onExit() {
        log.info("################ System down start ################");
        try {
            InetAddress ip = InetAddress.getLocalHost();
            String hostname = ip.getHostName();

        } catch (Exception e) {
            log.error("", e);
        }
        log.info("################ System down end ################");
    }
}
