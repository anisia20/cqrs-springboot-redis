package kr.co.uplus.common.components;

import java.time.Duration;
import java.util.Arrays;
import java.util.Hashtable;

import org.iptime.glegend.common.command.JsonCmd;
import org.iptime.glegend.common.command.JwtCmd;
import org.iptime.glegend.common.config.ModelMapperG;
import org.iptime.glegend.config.redis.command.RedisCmd;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import lombok.Data;
import lombok.extern.log4j.Log4j2;

@Configuration
@Data
@Log4j2
public class CommonResourceManager {
    protected static Hashtable<String, Object> resources = new Hashtable<String, Object>();

    @Autowired
    RedisCmd redisCmd;

    @Autowired
    JsonCmd jsonCmd;

    @Autowired
    JwtCmd jwtCmd;

    @Autowired
    ModelMapperG modelMapper;

    /**
     * @param key
     * @param obj
     */
    public synchronized void put(String key, Object obj){
        try {
            if(resources.containsKey(key))
                throw new Exception("key=["+key+"] already exists");

            resources.put(key, obj);
        } catch (Exception e) {
            log.error(e.toString());
        }
    }

    public Object get(String key){
        try {
            Object obj = resources.get(key);
            if(obj==null)
                throw new Exception("key=["+key+"] not found.");

            return resources.get(key);
        } catch (Exception e) {
            log.error(e.toString());
            return null;
        }
    }
}
