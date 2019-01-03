package org.wf.jwtp.provider;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.wf.jwtp.util.TokenUtil;

import java.security.Key;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * redis存储token的实现
 * Created by wangfan on 2018-12-29 上午 9:10.
 */
public class RedisTokenStore implements TokenStore {
    private static final String KEY_TOKEN_KEY = "oauth_token_key";
    private static final String KEY_PRE_TOKEN = "oauth_token:";
    private static final String KEY_PRE_PERM = "oauth_prem:";
    private static final String KEY_PRE_ROLE = "oauth_role:";

    private StringRedisTemplate redisTemplate;

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
    public Token createNewToken(String userId, String[] permissions, String[] roles) {
        return createNewToken(userId, permissions, roles, TokenUtil.DEFAULT_EXPIRE);
    }

    @Override
    public Token createNewToken(String userId, String[] permissions, String[] roles, long expire) {
        Token token = TokenUtil.buildToken(userId, expire, TokenUtil.parseHexKey(getTokenKey()));
        token.setPermissions(permissions);
        token.setRoles(roles);
        if (storeToken(token) > 0) {
            if (Config.getInstance().getMaxToken() != null && Config.getInstance().getMaxToken() != -1) {
                List<Token> userTokens = findTokensByUserId(userId);
                if (userTokens.size() > Config.getInstance().getMaxToken()) {
                    for (int i = 0; i < userTokens.size() - Config.getInstance().getMaxToken(); i++) {
                        removeToken(userId, userTokens.get(i).getAccessToken());
                    }
                }
            }
            return token;
        }
        return null;
    }

    @Override
    public int storeToken(Token token) {
        // 存储access_token
        redisTemplate.opsForList().rightPush(KEY_PRE_TOKEN + token.getUserId(), token.getAccessToken());
        // 存储权限
        String permKey = KEY_PRE_PERM + token.getUserId();
        for (int i = 0; i < redisTemplate.opsForSet().size(permKey); i++) {
            redisTemplate.opsForSet().pop(permKey);
        }
        redisTemplate.opsForSet().add(permKey, token.getPermissions());
        // 存储角色
        String roleKey = KEY_PRE_ROLE + token.getUserId();
        for (int i = 0; i < redisTemplate.opsForSet().size(roleKey); i++) {
            redisTemplate.opsForSet().pop(roleKey);
        }
        redisTemplate.opsForSet().add(roleKey, token.getRoles());
        return 1;
    }

    @Override
    public Token findToken(String userId, String access_token) {
        if (userId != null && !userId.trim().isEmpty()) {
            if (redisTemplate.opsForSet().isMember(KEY_PRE_TOKEN + userId, access_token)) {
                Token token = new Token();
                token.setUserId(userId);
                token.setAccessToken(access_token);
                token.setPermissions(setToArray(redisTemplate.opsForSet().members(KEY_PRE_PERM + userId)));
                token.setRoles(setToArray(redisTemplate.opsForSet().members(KEY_PRE_ROLE + userId)));
                return token;
            }
        }
        return null;
    }

    @Override
    public List<Token> findTokensByUserId(String userId) {
        List<Token> tokens = new ArrayList<Token>();
        Set<String> accessTokens = redisTemplate.opsForSet().members(KEY_PRE_TOKEN + userId);
        if (accessTokens != null || accessTokens.size() > 0) {
            String[] perms = setToArray(redisTemplate.opsForSet().members(KEY_PRE_PERM + userId));
            String[] roles = setToArray(redisTemplate.opsForSet().members(KEY_PRE_ROLE + userId));
            Iterator<String> iterator = accessTokens.iterator();
            while (iterator.hasNext()) {
                Token token = new Token();
                token.setAccessToken(iterator.next());
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
        redisTemplate.opsForSet().remove(KEY_PRE_TOKEN + userId, access_token);
        return 1;
    }

    @Override
    public int removeTokensByUserId(String userId) {
        String tPreKey = KEY_PRE_TOKEN + userId;
        for (int i = 0; i < redisTemplate.opsForSet().size(tPreKey); i++) {
            redisTemplate.opsForSet().pop(tPreKey);
        }
        return 1;
    }

    @Override
    public int updateRolesByUserId(String userId, String[] roles) {
        String roleKey = KEY_PRE_ROLE + userId;
        for (int i = 0; i < redisTemplate.opsForSet().size(roleKey); i++) {
            redisTemplate.opsForSet().pop(roleKey);
        }
        redisTemplate.opsForSet().add(roleKey, roles);
        return 1;
    }

    @Override
    public int updatePermissionsByUserId(String userId, String[] permissions) {
        String permKey = KEY_PRE_PERM + userId;
        for (int i = 0; i < redisTemplate.opsForSet().size(permKey); i++) {
            redisTemplate.opsForSet().pop(permKey);
        }
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
