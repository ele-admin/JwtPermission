package org.wf.jwtp.provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.wf.jwtp.util.TokenUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * redis存储token的实现
 * Created by wangfan on 2018-12-29 上午 9:10.
 */
public class RedisTokenStore implements TokenStore {
    private StringRedisTemplate redisTemplate;
    protected final Log logger = LogFactory.getLog(this.getClass());
    private static final String KEY_TOKEN_KEY = "oauth_token_key";  // tokenKey存储的key
    private static final String KEY_PRE_TOKEN = "oauth_token:";  // token存储的key前缀

    public RedisTokenStore(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public String getTokenKey() {
        String tokenKey = redisTemplate.opsForValue().get(KEY_TOKEN_KEY);
        if (tokenKey == null || tokenKey.trim().isEmpty()) {
            tokenKey = TokenUtil.getHexKey();
            redisTemplate.opsForValue().set(KEY_TOKEN_KEY, tokenKey);
        }
        return tokenKey;
    }

    @Override
    public Token createNewToken(String userId) {
        return createNewToken(userId, TokenUtil.DEFAULT_EXPIRE);
    }

    @Override
    public Token createNewToken(String userId, long expire) {
        String tokenKey = getTokenKey();
        logger.debug("TOKEN_KEY: " + tokenKey);
        Token token = TokenUtil.buildToken(userId, expire, TokenUtil.parseHexKey(tokenKey));
        if (storeToken(token) > 0) {
            if (maxToken != -1) {  // 限制用户的最大token数量
                Long userTokenSize = redisTemplate.opsForList().size(KEY_PRE_TOKEN + userId);
                if (userTokenSize > maxToken) {
                    for (int i = 0; i < userTokenSize - maxToken; i++) {
                        redisTemplate.opsForList().leftPop(KEY_PRE_TOKEN + userId);
                    }
                }
            }
            return token;
        }
        return null;
    }

    @Override
    public int storeToken(Token token) {
        redisTemplate.opsForList().rightPush(KEY_PRE_TOKEN + token.getUserId(), token.getAccessToken());
        return 1;
    }

    @Override
    public Token findToken(String userId, String access_token) {
        if (userId != null && !userId.trim().isEmpty()) {
            List<String> accessTokens = redisTemplate.opsForList().range(KEY_PRE_TOKEN + userId, 0, -1);
            for (int i = 0; i < accessTokens.size(); i++) {
                if (accessTokens.get(i).equals(access_token)) {
                    Token token = new Token();
                    token.setUserId(userId);
                    token.setAccessToken(access_token);
                    return token;
                }
            }
        }
        return null;
    }

    @Override
    public List<Token> findTokensByUserId(String userId) {
        if (userId == null || userId.trim().isEmpty()) {
            return null;
        }
        List<Token> tokens = new ArrayList<Token>();
        List<String> accessTokens = redisTemplate.opsForList().range(KEY_PRE_TOKEN + userId, 0, -1);
        if (accessTokens != null || accessTokens.size() > 0) {
            String[] perms = setToArray(redisTemplate.opsForSet().members(KEY_PRE_PERM + userId));
            String[] roles = setToArray(redisTemplate.opsForSet().members(KEY_PRE_ROLE + userId));
            for (int i = 0; i < accessTokens.size(); i++) {
                Token token = new Token();
                token.setAccessToken(accessTokens.get(i));
                token.setUserId(userId);
                token.setPermissions(perms);
                token.setRoles(roles);
                tokens.add(token);
            }
        }
        return tokens;
    }

    @Override
    public int removeToken(String userId, String access_token) {
        redisTemplate.opsForList().remove(KEY_PRE_TOKEN + userId, 0, access_token);
        return 1;
    }

    @Override
    public int removeTokensByUserId(String userId) {
        redisTemplate.delete(KEY_PRE_TOKEN + userId);
        return 1;
    }

    @Override
    public int updateRolesByUserId(String userId, String[] roles) {
        String roleKey = KEY_PRE_ROLE + userId;
        redisTemplate.delete(roleKey);
        redisTemplate.opsForSet().add(roleKey, roles);
        return 1;
    }

    @Override
    public int updatePermissionsByUserId(String userId, String[] permissions) {
        String permKey = KEY_PRE_PERM + userId;
        redisTemplate.delete(permKey);
        redisTemplate.opsForSet().add(permKey, permissions);
        return 1;
    }

    private String[] setToArray(Set<String> set) {
        if (set == null) {
            return null;
        }
        return set.toArray(new String[set.size()]);
    }
}
