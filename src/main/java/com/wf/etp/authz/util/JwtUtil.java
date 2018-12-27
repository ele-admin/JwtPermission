package com.wf.etp.authz.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

/**
 * Jwt工具类
 * Created by 王帆 on 2018-09-21 上午 11:52.
 */
public class JwtUtil {
    private static final String hexKey = "74f0ab21bcda34c866604d48ce32dfb0c94385436c1de660cdce1f6b0431ef07";
    public static final int expire = 60 * 60 * 24;  // 过期时长,单位秒

    /**
     * 生成token
     */
    public static String buildToken(String subject) {
        Date expireDate = new Date(new Date().getTime() + 1000 * expire);  // 单位毫秒
        String jws = Jwts.builder().setSubject(subject).signWith(getKey(hexKey)).setExpiration(expireDate).compact();
        return jws;
    }

    /**
     * 解析token
     */
    public static String parseToken(String token) {
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(getKey(hexKey)).parseClaimsJws(token);
        return claimsJws.getBody().getSubject();
    }

    /**
     * 生成Key
     */
    public static Key getKey() {
        return Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    /**
     * 把16进制的key转成Key
     */
    public static Key getKey(String hexKey) {
        SecretKey key = Keys.hmacShaKeyFor(Hex.decode(hexKey));
        return key;
    }

    /**
     * 生成16进制的key
     */
    public static String getHexKey() {
        return Hex.encodeToString(getKey().getEncoded());
    }

}
