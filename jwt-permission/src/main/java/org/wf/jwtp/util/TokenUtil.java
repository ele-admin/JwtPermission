package org.wf.jwtp.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.wf.jwtp.provider.Token;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

/**
 * Token工具类
 * <p>
 * Created by wangfan on 2018-1-21 下午4:30:59
 */
public class TokenUtil {
    public static final long DEFAULT_EXPIRE = 60 * 60 * 24;  // 默认过期时长,单位秒

    /**
     * 生成token
     *
     * @param subject 载体
     * @return Token
     */
    public static Token buildToken(String subject) {
        return buildToken(subject, DEFAULT_EXPIRE);
    }

    /**
     * 生成token
     *
     * @param subject 载体
     * @param expire  过期时间，单位秒
     * @return Token
     */
    public static Token buildToken(String subject, long expire) {
        return buildToken(subject, expire, getKey());
    }

    /**
     * 生成token
     *
     * @param subject 载体
     * @param expire  过期时间，单位秒
     * @param key     密钥
     * @return Token
     */
    public static Token buildToken(String subject, long expire, Key key) {
        // 生成access_token
        Date expireDate = new Date(new Date().getTime() + 1000 * expire);
        String access_token = Jwts.builder().setSubject(subject).signWith(key).setExpiration(expireDate).compact();
        // 生成refresh_token
        Date refreshExpireDate = new Date(new Date().getTime() + 1000 * expire * 2);
        String refresh_token = Jwts.builder().setSubject(subject).signWith(key).setExpiration(refreshExpireDate).compact();
        // 返回Token
        Token token = new Token();
        token.setAccessToken(access_token);
        token.setRefreshToken(refresh_token);
        token.setUserId(subject);
        token.setExpireTime(expireDate);
        return token;
    }

    /**
     * 解析token
     *
     * @param token  token
     * @param hexKey 16进制密钥
     * @return 载体
     */
    public static String parseToken(String token, String hexKey) {
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(parseHexKey(hexKey)).parseClaimsJws(token);
        return claimsJws.getBody().getSubject();
    }

    /**
     * 生成密钥Key
     *
     * @return Key
     */
    public static Key getKey() {
        return Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    /**
     * 生成16进制的key
     *
     * @return hexKey
     */
    public static String getHexKey() {
        return getHexKey(getKey());
    }

    /**
     * 生成16进制的key
     *
     * @param key 密钥Key
     * @return hexKey
     */
    public static String getHexKey(Key key) {
        return Hex.encodeToString(key.getEncoded());
    }

    /**
     * 把16进制的key解析成Key
     *
     * @param hexKey 16进制key
     * @return Key
     */
    public static Key parseHexKey(String hexKey) {
        if (hexKey == null || hexKey.trim().isEmpty()) {
            return null;
        }
        SecretKey key = Keys.hmacShaKeyFor(Hex.decode(hexKey));
        return key;
    }

}
