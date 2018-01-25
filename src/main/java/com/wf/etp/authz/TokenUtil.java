package com.wf.etp.authz;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.Base64Codec;

import java.security.Key;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

/**
 * Token工具类
 * 
 * @author wangfan
 * @date 2018-1-21 下午4:30:59
 */
public class TokenUtil {

	/**
	 * 由字符串生成加密key
	 * 
	 * @return
	 */
	private static Key generalKey() {
		byte[] encodedKey = Base64Codec.BASE64.encode("e-t-p".getBytes()).getBytes();
		return new SecretKeySpec(encodedKey, "AES");
	}

	/**
	 * 创建token
	 * 
	 * @param userId
	 * @param ttlMillis
	 * @return
	 * @throws Exception
	 */
	public static String createToken(String userId, long ttlMillis) {
		long nowMillis = System.currentTimeMillis();
		String token = Jwts.builder().setSubject(userId)
				.signWith(SignatureAlgorithm.HS256, generalKey())
				.setIssuedAt(new Date(nowMillis))
				.setExpiration(new Date(nowMillis + ttlMillis)).compact();
		SubjectUtil.getInstance().setCacheToken(userId, token);
		return token;
	}

	/**
	 * 解析token
	 * 
	 * @param token
	 * @return
	 * @throws Exception
	 */
	public static Claims parseToken(String token) throws Exception {
		if (token == null) {
			throw new NullPointerException("token不能为null");
		}
		return Jwts.parser().setSigningKey(generalKey()).parseClaimsJws(token).getBody();
	}
	
}
