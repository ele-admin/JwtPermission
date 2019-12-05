package org.wf.jwtp.provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.wf.jwtp.util.TokenUtil;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * redis存储token的实现
 * Created by wangfan on 2018-12-29 上午 9:10.
 */
public class RedisTokenStore extends TokenStore {
    private StringRedisTemplate redisTemplate;
    private final JdbcTemplate jdbcTemplate;
    protected final Log logger = LogFactory.getLog(this.getClass());
    private static final String KEY_TOKEN_KEY = "oauth_token_key";  // tokenKey存储的key
    private static final String KEY_PRE_TOKEN = "oauth_token:";  // token存储的key前缀
    private static final String KEY_PRE_ROLE = "oauth_role:";  // 角色存储的key前缀
    private static final String KEY_PRE_PERM = "oauth_prem:";  // 权限存储的key前缀

    public RedisTokenStore(StringRedisTemplate redisTemplate) {
        this(redisTemplate, null);
    }

    public RedisTokenStore(StringRedisTemplate redisTemplate, DataSource dataSource) {
        this.redisTemplate = redisTemplate;
        if (dataSource != null) {
            this.jdbcTemplate = new JdbcTemplate(dataSource);
        } else {
            this.jdbcTemplate = null;
        }
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
        return createNewToken(userId, null, null);
    }

    @Override
    public Token createNewToken(String userId, long expire) {
        return createNewToken(userId, null, null, expire);
    }

    @Override
    public Token createNewToken(String userId, String[] permissions, String[] roles) {
        return createNewToken(userId, permissions, roles, TokenUtil.DEFAULT_EXPIRE);
    }

    @Override
    public Token createNewToken(String userId, String[] permissions, String[] roles, long expire) {
        String tokenKey = getTokenKey();
        logger.debug("TOKEN_KEY: " + tokenKey);
        Token token = TokenUtil.buildToken(userId, expire, TokenUtil.parseHexKey(tokenKey));
        token.setRoles(roles);
        token.setPermissions(permissions);
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
        // 存储access_token
        redisTemplate.opsForList().rightPush(KEY_PRE_TOKEN + token.getUserId(), token.getAccessToken());
        // 存储角色
        updateRolesByUserId(token.getUserId(), token.getRoles());
        // 存储权限
        updatePermissionsByUserId(token.getUserId(), token.getPermissions());
        return 1;
    }

    @Override
    public Token findToken(String userId, String access_token) {
        List<Token> tokens = findTokensByUserId(userId);
        if (tokens != null && access_token != null) {
            for (Token token : tokens) {
                if (access_token.equals(token.getAccessToken())) {
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
        if (accessTokens != null && accessTokens.size() > 0) {
            for (int i = 0; i < accessTokens.size(); i++) {
                Token token = new Token();
                token.setUserId(userId);
                token.setAccessToken(accessTokens.get(i));
                // 查询权限
                token.setPermissions(setToArray(redisTemplate.opsForSet().members(KEY_PRE_PERM + userId)));
                // 查询角色
                token.setRoles(setToArray(redisTemplate.opsForSet().members(KEY_PRE_ROLE + userId)));
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
        if (roles != null) {
            redisTemplate.opsForSet().add(roleKey, roles);
        }
        return 1;
    }

    @Override
    public int updatePermissionsByUserId(String userId, String[] permissions) {
        String permKey = KEY_PRE_PERM + userId;
        redisTemplate.delete(permKey);
        if (permissions != null) {
            redisTemplate.opsForSet().add(permKey, permissions);
        }
        return 1;
    }

    @Override
    public String[] findRolesByUserId(String userId, Token token) {
        // 判断是否自定义查询
        if (findRolesSql == null || findRolesSql.trim().isEmpty()) {
            return token.getRoles();
        }
        if (jdbcTemplate != null) {
            String rolesJson = null;
            try {
                rolesJson = jdbcTemplate.queryForObject(findRolesSql, String.class);
            } catch (EmptyResultDataAccessException e) {
            }
            if (rolesJson != null && !rolesJson.trim().isEmpty()) {
                try {
                    com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                    List<String> list = mapper.readValue(rolesJson, mapper.getTypeFactory().constructParametricType(ArrayList.class, String.class));
                    return strListToArray(list);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }

    @Override
    public String[] findPermissionsByUserId(String userId, Token token) {
        // 判断是否自定义查询
        if (findPermissionsSql == null || findPermissionsSql.trim().isEmpty()) {
            return token.getPermissions();
        }
        if (jdbcTemplate != null) {
            String permsJson = null;
            try {
                permsJson = jdbcTemplate.queryForObject(findPermissionsSql, String.class);
            } catch (EmptyResultDataAccessException e) {
            }
            if (permsJson != null && !permsJson.trim().isEmpty()) {
                try {
                    com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                    List<String> list = mapper.readValue(findPermissionsSql, mapper.getTypeFactory().constructParametricType(ArrayList.class, String.class));
                    return strListToArray(list);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }

    /**
     * setToArray
     */
    private String[] setToArray(Set<String> set) {
        if (set == null) {
            return null;
        }
        return set.toArray(new String[set.size()]);
    }

    /**
     * strListToArray
     */
    private String[] strListToArray(List<String> list) {
        if (list == null) {
            return null;
        }
        String[] objects = new String[list.size()];
        for (int i = 0; i < list.size(); i++) {
            objects[i] = list.get(i);
        }
        return objects;
    }

}
