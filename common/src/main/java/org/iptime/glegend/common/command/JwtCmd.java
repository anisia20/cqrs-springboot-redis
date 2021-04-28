package org.iptime.glegend.common.command;

import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.JwtMap;
import lombok.extern.log4j.Log4j2;

@Log4j2
@Component
public class JwtCmd {

    @Autowired
    JsonCmd jsonCmd;

    public static String jwtTyp = "JWT";
    public static String jwtIss = "glegend";
    public static String jwtSecretKey = "glegend";
	public static long jwtExpTimeMilli = 30*1000; // test용도
    public static long jwtExpTimeRefreshMilli = 25*60*60*1000;

    public Claims getPayload(String token) {
        try {
            String[] body = token.split("\\.");
            if (body.length != 3) {
                log.debug("token is incorrect. token len={}, d={}", body.length, token);
                return null;
            }
            byte[] payload = Base64.getDecoder().decode(body[1]);
            JwtMap map = (JwtMap) jsonCmd.jsonStringToObj(new String(payload), JwtMap.class);

            Claims claims = null;
            if (map != null) claims = new DefaultClaims(map);

            return claims;
        } catch(Exception e) {
            log.warn("Payload cannot gathering. err={}", e.getMessage());
            return null;
        }
    }

    public String getSubject(String token) {
        if (getPayload(token) == null) return null;
        return getPayload(token).getSubject();
    }

    public Boolean isTokenRefresh(String token) {
        Claims map = getPayload(token);
        if (map == null) return true;

        Date expiration = map.getExpiration();
        if (expiration == null) return true;

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(expiration);
        calendar.add(Calendar.SECOND, -10);
        return calendar.getTime().before(new Date());
    }

    public Claims getAllClaimsFromToken(String token) {
        return getPayload(token);
    }

    public Date getExpirationDateFromToken(String token) {
        Claims map = getPayload(token);
        if (map == null) return null;

        return map.getExpiration();
    }

    public Boolean isTokenExpired(String token) {
        Date expiration = getExpirationDateFromToken(token);
        if (expiration == null) return true;

        return expiration.before(new Date());
    }

    private Claims getAllClaimsFromToken(String jwtCliSecretKey, String token) {
        Claims claims = null;

        try {
            claims = Jwts.parser().setSigningKey(jwtCliSecretKey).parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e) {
            log.warn("expired token, payload={}", getPayload(token));
        } catch (UnsupportedJwtException e) {
            log.error("not supported token, payload={}", getPayload(token));
        } catch (MalformedJwtException e) {
            log.error("incorrected token, payload={}", getPayload(token));
        } catch (SignatureException e) {
            log.error("invalid signature, payload={}", getPayload(token));
        } catch (IllegalArgumentException e) {
            log.error("unknown token, payload={}", getPayload(token));
        }

        return claims;
    }

    private Date getExpirationDateFromToken(String jwtCliSecretKey, String token) {
        try {
            return getAllClaimsFromToken(jwtCliSecretKey, token).getExpiration();
        } catch (Exception e) {
            return null;
        }
    }

    private Boolean isTokenExpired(String jwtCliSecretKey, String token) {
        Date expiration = getExpirationDateFromToken(jwtCliSecretKey, token);
        if (expiration == null) return true;
        return expiration.before(new Date());
    }

    public Boolean validateToken(String jwtCliSecretKey, String token) {
        return !isTokenExpired(jwtCliSecretKey, token);
    }
    public String getToken(
            String jwtCliSecretKey,
            String cliId,
            String ipPattern,
            String accessUrl,
            boolean isRefresh
    ) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sIp", ipPattern); // 인증요청한 클라이언트 아이피
        claims.put("accessUrl", accessUrl); // 허용가능한 url
        return genToken(jwtCliSecretKey, jwtExpTimeMilli, jwtExpTimeRefreshMilli, jwtIss, cliId, claims, isRefresh);
    }

    public String getToken(
            String jwtCliSecretKey,
            String cliId,
            String accessUrl,
            boolean isRefresh
    ) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("accessUrl", accessUrl); // 허용가능한 url
        return genToken(jwtCliSecretKey, jwtExpTimeMilli, jwtExpTimeRefreshMilli, jwtIss, cliId, claims, isRefresh);
    }

    public String getToken(
            String cliId,
            String accessUrl,
            boolean isRefresh
    ) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("accessUrl", accessUrl); // 허용가능한 url
        return genToken(jwtSecretKey, jwtExpTimeMilli, jwtExpTimeRefreshMilli, jwtIss, cliId, claims, isRefresh);
    }

    private String genToken(
            String jwtSecretKey,
            long jwtExpTimeMilli,
            long jwtExpTimeRefreshMilli,
            String jwtIss,
            String id,
            Map<String, Object> claims,
            boolean isRefresh
    ) {
        try {
            Date createdDate = new Date();

            claims.put(Claims.ISSUER, jwtIss);
            claims.put("typ", jwtTyp);

            Date expirationDate = null;
            if (isRefresh)
                expirationDate = new Date(createdDate.getTime() + jwtExpTimeRefreshMilli);
            else
                expirationDate = new Date(createdDate.getTime() + jwtExpTimeMilli);

            return Jwts.builder()
                    .setClaims(claims)
//					.setPayload( claims )
                    .setSubject(id)
                    .setIssuedAt(createdDate)
                    .setExpiration(expirationDate)
                    .signWith(SignatureAlgorithm.HS256, jwtSecretKey)
                    .compact();

        } catch(Exception e) {
            log.error("JWT generate fail. e={}", e.getMessage(), e);
            return "";
        }
    }

}
