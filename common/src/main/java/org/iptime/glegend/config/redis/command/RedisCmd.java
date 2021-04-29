package org.iptime.glegend.config.redis.command;

import lombok.extern.log4j.Log4j2;
import org.iptime.glegend.common.util.TimeG;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.DataType;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;

import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.ZSetOperations.TypedTuple;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Log4j2
@Configuration
public class RedisCmd {

    @Autowired
    @Qualifier("redisTemplate")
    private RedisTemplate<String, Object> template;

    public RedisConnectionFactory getConnectionFactory() {
        return template.getConnectionFactory();
    }

    public RedisConnection getConnection() {
        try {
            return template.getConnectionFactory().getConnection();
        } catch(Exception e) {
            log.error("getConnection error. e={}", e.getMessage());
            return null;
        }
    }

    public String genKey(String redisKeyType, String subKey) {
        return redisKeyType.replaceAll("\\{sub\\}", subKey);
    }

    public boolean set(String key, Object obj) {
        return set(key, obj, -1);
    }

    public boolean set(String key, Object obj, long expire) {
        boolean b = true;
        try {
            template.opsForValue().set(key, obj);
            if (expire > 0) setKeyExpire(key, expire);
        } catch (Exception e) {
            b = false;
            log.error(e.toString());
        }
        return b;
    }

    public Object get(String key) {
        Object r = null;
        try {
            r = template.opsForValue().get(key);
            r = nvl(r);
        } catch (Exception e) {
            r = null;
            log.error(e.toString());
        }
        return r;
    }

    public boolean hput(String key, String field, Object obj) {
        boolean b = true;
        try {
            template.opsForHash().put(key, field, obj);
        } catch (Exception e) {
            log.error(e.toString());
            b = false;
        }
        return b;
    }

    public boolean hput(String key, String field, Object obj, long expire) {
        boolean b = true;
        try {
            template.opsForHash().put(key, field, obj);
            if (expire > 0) setKeyExpire(key, expire);
        } catch (Exception e) {
            log.error(e.toString());
            b = false;
        }
        return b;
    }

    public Object hget(String key, String field) {
        Object r = null;
        try {
            r = template.opsForHash().get(key, field);
        } catch (Exception e) {
            r = null;
            log.error(e.toString());
        }
        return r;
    }

    /**
     * Hash 키의 필드/값 목록 조회
     * @param key
     * @return
     */
    public Map<Object, Object> hgetAll(String key) {
        Map<Object, Object> r = null;
        try {
            r = template.opsForHash().entries(key);
        } catch (Exception e) {
            r = null;
            log.error(e.toString());
        }
        return r;
    }

    /**
     * Hash 키의 필드목록 조회
     * @param key
     * @return
     */
    public Set<Object> hgetAllField(String key) {
        Set<Object> r = null;
        try {
            r = template.opsForHash().keys(key);
        } catch (Exception e) {
            r = null;
            log.error(e.toString());
        }
        return r;
    }

    public boolean hdelete(String key, String field) {

        boolean b = true;
        try {
            template.opsForHash().delete(key, field);
        } catch (Exception e) {
            b = false;
            log.error(e.toString());
        }
        return b;
    }

    public boolean delete(String key) {

        boolean b = true;
        try {
            template.delete(key);
        } catch (Exception e) {
            b = false;
            log.error(e.toString());
        }
        return b;
    }

    public long push(String key, Object obj) {
        return lPush(key, obj, 0);
    }

    public long push(String key, Object obj, long expire) {
        return lPush(key, obj, expire);
    }

    public long lPush(String key, Object obj, long expire) {
        long r = 0;
        try {
            r = template.opsForList().leftPush(key, obj);
            if (expire > 0) setKeyExpire(key, expire);
        } catch (Exception e) {
            r = -1;
            log.error(e.toString());
        }

        return r;
    }

    public long ldelete(String key, Object obj) {
        long r = 0;
        try {
            r = template.opsForList().remove(key, 1, obj);
        } catch (Exception e) {
            r = -1;
            log.error(e.toString());
        }

        return r;
    }

    public long rPush(String key, Object obj) {
        long r = 0;
        try {
            r = template.opsForList().rightPush(key, obj);
        } catch (Exception e) {
            r = -1;
            log.error(e.toString());
        }
        return r;
    }

    public long rPush(String key, Object obj, long expire) {
        long r = 0;
        try {
            r = template.opsForList().rightPush(key, obj);
            if (expire > 0) setKeyExpire(key, expire);
        } catch (Exception e) {
            r = -1;
            log.error(e.toString());
        }
        return r;
    }

    public Object pop(String key) {
        return rPop(key);
    }

    public Object index(String key, int index) {
        Object r = null;
        try {
            r = template.opsForList().index(key, index);
        } catch (Exception e) {
            r = null;
            log.error(e.toString());
        }
        return r;
    }

    public Object rPop(String key) {
        Object r = null;
        try {
            r = template.opsForList().rightPop(key);
        } catch (Exception e) {
            r = null;
            log.error(e.toString());
        }
        return r;
    }

    public Object lPop(String key) {
        Object r = null;
        try {
            r = template.opsForList().leftPop(key);
        } catch (Exception e) {
            r = null;
            log.error(e.toString());
        }
        return r;
    }

    public Object rPop(String key, int blockTimeOut) {
        Object r = null;
        try {
            r = template.opsForList().rightPop(key, blockTimeOut, TimeUnit.SECONDS);
            r = nvl(r);
        } catch (Exception e) {
            r = null;
            log.error(e.toString());
        }
        return r;
    }

    public List<Object> rangeList(String key, int start, int end) {
        List<Object> r = null;
        try {
            r = template.opsForList().range(key, start, end);
        } catch (Exception e) {
            r = null;
            log.error(e.toString());
        }
        return r;
    }

    public long getKeyExpire(String key) {

        long sec = 0;
        try {
            sec = template.getExpire(key, TimeUnit.SECONDS);
        } catch (Exception e) {
            sec = -1l;
            log.error(e.toString());
        }
        return sec;
    }

    public boolean setKeyExpire(String key, long expireSec) {
        boolean b = true;
        try {
            template.expire(key, expireSec, TimeUnit.SECONDS);
        } catch (Exception e) {
            b = false;
            log.error(e.toString());
        }
        return b;
    }

    public boolean setKeyPersist(String key) {
        boolean b = true;
        try {
            template.persist(key);
        } catch (Exception e) {
            b = false;
            log.error(e.toString());
        }
        return b;
    }

    public boolean hasKey(String key) {
        boolean b = true;
        try {
            b = template.hasKey(key);
        } catch (Exception e) {
            b = false;
            log.error(e.toString());
        }
        return b;
    }

    public boolean hasField(String key, String field) {
        boolean b = true;
        try {
            b = template.opsForHash().hasKey(key, field);
        } catch (Exception e) {
            b = false;
            log.error(e.toString());
        }
        return b;
    }

    public Long incField(String key, String field, long increment) {

        long l = 0l;
        try {
            l = template.opsForHash().increment(key, field, increment);
        } catch (Exception e) {
            l = -1;
            log.error(e.toString());
        }
        return l;
    }

    public Long incValue(String key) {
        Long l = 0l;
        try {
            l = template.opsForValue().increment(key);
            if (l == null) {
                log.error("increment value is null. K={}", key);
                l = -1L;
            }
        } catch (Exception e) {
            l = -1L;
            log.error(e.toString());
        }
        return l;
    }

    public long hsize(String key) {
        long l = 0L;
        try {
            l = template.opsForHash().size(key);
        } catch (Exception e) {
            l = -1;
            log.error(e.toString());
        }
        return l;
    }

    public long qsize(String redisKeyType) {
        long l = 0L;
        try {
            l = template.opsForList().size(redisKeyType);
        } catch (Exception e) {
            l = -1;
            log.error("qsize error. RK={}, err={}", redisKeyType, e.getMessage());
        }
        return l;
    }

    public long size(String redisKey) {
        long l = 0L;
        try {
            DataType dType = template.type(redisKey);
            if(dType.equals(DataType.HASH)) {
                l = template.opsForHash().size(redisKey);
            }else if(dType.equals(DataType.LIST)) {
                l = template.opsForList().size(redisKey);
            }else if(dType.equals(DataType.SET)) {
                l = template.opsForSet().size(redisKey);
            }else if(dType.equals(DataType.ZSET)) {
                l = template.opsForZSet().size(redisKey);
            }
        } catch (Exception e) {
            l = -1;
            log.error(e.toString());
        }
        return l;
    }


    public List<String> getKeyList( String pattern ) {
        List<String> rslt = new ArrayList<String>();
        try {
            Set<String> keys = template.keys(pattern);
            if (keys == null) return null;

            rslt.addAll(keys);
        } catch (Exception e) {
            log.error(e.toString());
        }
        return rslt;
    }

    public List<String> getKeyList( String pattern, Integer n_res ) {
        List<String> rslt = new ArrayList<String>();
        try {
            Set<String> keys = template.keys(pattern);
            if (keys == null) {
                n_res = -2;
                return null;
            }

            rslt.addAll(keys);
        } catch (Exception e) {
            log.error(e.toString());
            n_res = -3;
        }
        return rslt;
    }

    public HashMap<String, Object> getValueList( String key, String pattern ) {
        HashMap<String, Object> result = new HashMap<>();
        Cursor<Entry<Object, Object>> rslt = null;
        try {
            ScanOptions options = ScanOptions.scanOptions().match(pattern).build();
            rslt = template.opsForHash().scan(key, options);
            if (rslt == null) return null;

            while(rslt.hasNext()) {
                Entry<Object, Object> bytes = rslt.next();
                result.put((String) bytes.getKey(), bytes.getValue());
            }

        } catch (Exception e) {
            log.error(e.toString());
        } finally {
            if (rslt != null) try { rslt.close(); } catch (Exception e) {}
        }
        return result;
    }

    public HashMap<String, Object> getFieldList( String key, String pattern ) {
        HashMap<String, Object> result = new HashMap<>();
        Cursor<Entry<Object, Object>> rslt = null;
        try {
            ScanOptions options = ScanOptions.scanOptions().match(pattern).build();
            rslt = template.opsForHash().scan(key, options);
            if (rslt == null) return null;

            while(rslt.hasNext()) {
                Entry<Object, Object> bytes = rslt.next();
                result.put((String) bytes.getKey(), bytes.getKey());
            }

        } catch (Exception e) {
            log.error(e.toString());
        } finally {
            if (rslt != null) try { rslt.close(); } catch (Exception e) {}
        }
        return result;
    }

    Object nvl(Object s) {
        return s == null ? "" : s;
    }


    public int checkRedis() {
        try {
            String key = "RedisCmdHealthcheck";
            Object chk = template.expire(key, 10, TimeUnit.MILLISECONDS);
            return 1;
        } catch (Exception e){
            log.error(e.getMessage());
            return -1;
        }
    }

    public Set<Object> zRange(String key, double minScore, double maxScore, long offset, long count) {
        try {
            Set<Object> lst = template.opsForZSet().rangeByScore(key, minScore, maxScore, offset, count);
            return lst;
        } catch (Exception e){
            log.error(e.getMessage());
            return null;
        }
    }

    public Set<Object> zRange(String key, String pattern) {
        Cursor<TypedTuple<Object>> rslt = null;
        try {
            ScanOptions options = ScanOptions.scanOptions().match(pattern).build();
            rslt = template.opsForZSet().scan(key, options);
            if (rslt == null) return null;

            Set<Object> lst = new HashSet<>();
            while(rslt.hasNext()) {
                TypedTuple<Object> bytes = rslt.next();
                Object obj = bytes.getValue();
                lst.add(obj);
            }

            if (lst.size() == 0) return null;

            return lst;
        } catch (Exception e){
            log.error(e.getMessage());
            return null;
        } finally {
            if (rslt != null) { try { rslt.close(); } catch(Exception e) {} }
        }
    }

    public Long zRank(String key, Object obj) {
        Long r = null;
        try {
            r = template.opsForZSet().rank(key, obj);
        } catch (Exception e) {
            r = null;
            log.error(e.toString());
        }
        return r;
    }

    public long zPut(String key, Object value, double score) {
        try {
            boolean l_res = template.opsForZSet().add(key, value, score);
            return 1;
        } catch (Exception e){
            log.error(e.getMessage());
            return -1;
        }
    }

    public long zScore(String key, Object value) {
        try {
            Double l_res = template.opsForZSet().score(key, value);
            if (l_res == null) return -1;

            return l_res.longValue();
        } catch (Exception e){
            log.error(e.getMessage());
            return -2;
        }
    }

    public long zRemoveScore(String key, double minScore, double maxScore) {
        try {
            long l_res = template.opsForZSet().removeRangeByScore(key, minScore, maxScore);
            return l_res;
        } catch (Exception e){
            log.error(e.getMessage());
            return -1;
        }
    }

    public long zRemoveObj(String key, Object...objLst) {
        try {
            long l_res = template.opsForZSet().remove(key, objLst);
            return l_res;
        } catch (Exception e){
            log.error(e.getMessage());
            return -1;
        }
    }

    public long zSize(String key) {
        try {
            long l_res = template.opsForZSet().size(key);
            return l_res;
        } catch (Exception e){
            log.error(e.getMessage());
            return -1;
        }
    }

    public long zSize(String key, String date14) {
        try {
            long min = TimeG.toMillis(date14+"000", "yyyyMMddHHmmssSSS");
            long max = min+TimeG.ONE_SECOND_MILLIS-1;
            long l_res = template.opsForZSet().count(key, min, max);
            return l_res;
        } catch (Exception e){
            log.error(e.getMessage());
            return -1;
        }
    }

}