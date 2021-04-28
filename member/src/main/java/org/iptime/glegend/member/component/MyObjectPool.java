package org.iptime.glegend.member.component;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.aop.target.CommonsPool2TargetSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

@Component
public class MyObjectPool extends CommonsPool2TargetSource {

    public MyObjectPool() {
        setTargetBeanName("myObjectMapper");
        setMaxSize(100);
        setMaxIdle(20);
        setMaxWait(3000L);
    }

    @Bean(name = "myObjectMapper")
    @Scope(scopeName="prototype")
    public ObjectMapper getObjectMapper() {
        return new ObjectMapper();
    }
}
