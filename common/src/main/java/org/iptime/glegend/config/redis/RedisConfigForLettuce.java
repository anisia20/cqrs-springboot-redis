package org.iptime.glegend.config.redis;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.lettuce.core.ClientOptions;
import io.lettuce.core.TimeoutOptions;
import org.iptime.glegend.utils.Util;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.*;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;

public class RedisConfigForLettuce {

    @Value("${redis.mode}")
    private String mode;

    @Value("${redis.master}")
    private String master;

    @Value("${redis.db_num}")
    private int dbNum;

    @Value("${redis.password}")
    private String pwd;

    @Value("${redis.standalone.host}")
    private String sdHost;

    @Value("${redis.standalone.port}")
    private int sdPort;

    @Value("${redis.sentinels.host}")
    private String[] stHost;

    @Value("${redis.sentinels.port}")
    private int[] stPort;

    @Value("${redis.cluster.host}")
    private String[] ctHost;

    @Value("${redis.cluster.port}")
    private int[] ctPort;

    @Value("${redis.timeout.cmdSec}")
    private int cmdSec;

    @Value("${spring.profiles.active}")
    private String activeProfile;

    @Primary
    @Bean("connectionFactory")
    public RedisConnectionFactory connectionFactory() {

        LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
                .commandTimeout(Duration.ofSeconds(10))
                .shutdownTimeout(Duration.ofSeconds(10))
                .clientOptions(
                        ClientOptions.builder().autoReconnect(true).pingBeforeActivateConnection(true)
                                .timeoutOptions(TimeoutOptions.enabled(Duration.ofSeconds(cmdSec))).build())
                .build();

        if (Util.isNullOrEmpty(mode) || "standalone".equals(mode)) {
            RedisStandaloneConfiguration redisConf = new RedisStandaloneConfiguration();
            redisConf.setHostName(sdHost);
            redisConf.setPort(sdPort);
            redisConf.setDatabase(getDbNo());
            if (Util.isNullOrEmpty(pwd) == false) redisConf.setPassword(RedisPassword.of(pwd));

            return new LettuceConnectionFactory(redisConf, clientConfig);

        } else if ("sentinels".equals(mode)) {
            RedisSentinelConfiguration sentinelConfig = new RedisSentinelConfiguration();
            sentinelConfig.setMaster(master);
            sentinelConfig.setDatabase(getDbNo());
            if (Util.isNullOrEmpty(pwd) == false) sentinelConfig.setPassword(RedisPassword.of(pwd));

            RedisNode node = null;
            for (int i = 0; i < ctHost.length; i++) {
                node = new RedisNode(stHost[i], stPort[i]);
                sentinelConfig.addSentinel(node);
            }

            return new LettuceConnectionFactory(sentinelConfig);

        } else {
            RedisClusterConfiguration clusterConfig = new RedisClusterConfiguration();
            if (Util.isNullOrEmpty(pwd) == false) clusterConfig.setPassword(RedisPassword.of(pwd));

            RedisNode node = null;
            for (int i = 0; i < ctHost.length; i++) {
                node = new RedisNode(ctHost[i], ctPort[i]);
                clusterConfig.addClusterNode(node);
            }

            return new LettuceConnectionFactory(clusterConfig);
        }
    }

    // database cluster mode 지원안함
    public int getDbNo() {
        /**
         *  local: 2 or db_num(application.yml),
         *  dev : 1
         *  stg : 0
         *  prod : 0
         */
        if ("local".equals(activeProfile)) {
            if (Util.isNullOrEmpty(dbNum)) {
                return 2;
            } else {
                return dbNum;
            }

        } else if ("dev".equals(activeProfile)) {
            return 1;
        }
        return 0;
    }

    @Primary
    @Bean("redisTemplate")
    public RedisTemplate<String, Object> redisTemplate(@Qualifier("connectionFactory") RedisConnectionFactory factory) {

        ObjectMapper om = new ObjectMapper();
        om.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
        om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false); // Json 포멧 강제화 해제 (Unrecognized field 처리)

        Jackson2JsonRedisSerializer<Object> redisSerializer = new Jackson2JsonRedisSerializer<Object>(Object.class);
        redisSerializer.setObjectMapper(om);

        RedisTemplate<String, Object> template = new RedisTemplate<String, Object>();
        template.setKeySerializer(new StringRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());

        template.setValueSerializer(redisSerializer);
        template.setHashValueSerializer(redisSerializer);

        template.setConnectionFactory(factory);
        template.getConnectionFactory().getConnection();
        template.afterPropertiesSet();
        return template;
    }

}
