package org.wf.jwtp.provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.Assert;
import org.wf.jwtp.util.TokenUtil;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * jdbc存储token的实现
 * Created by wangfan on 2018-12-28 下午 1:00.
 */
public abstract class JdbcTokenStore implements TokenStore {
    protected final Log logger = LogFactory.getLog(this.getClass());
    private final JdbcTemplate jdbcTemplate;
    private RowMapper<Token> rowMapper = new TokenRowMapper();
    // sql
    private static final String UPDATE_FIELDS = "access_token, user_id, refresh_token, expire_time";
    private static final String BASE_SELECT = "select token_id, " + UPDATE_FIELDS + ", create_time from oauth_token";
    // 查询用户的某个token
    private static final String SQL_SELECT_BY_TOKEN = BASE_SELECT + " where user_id = ? and access_token = ?";
    // 查询某个用户的全部token
    private static final String SQL_SELECT_BY_USER_ID = BASE_SELECT + " where user_id = ? order by create_time";
    // 插入token
    private static final String SQL_INSERT = "insert into oauth_token (" + UPDATE_FIELDS + ") values (?,?,?,?,?,?)";
    // 删除某个用户指定token
    private static final String SQL_DELETE = "delete from oauth_token where user_id = ? and access_token = ?";
    // 删除某个用户全部token
    private static final String SQL_DELETE_BY_USER_ID = "delete from oauth_token where user_id = ?";
    // 查询tokenKey
    private static final String SQL_SELECT_KEY = "select token_key from oauth_token_key";
    // 插入tokenKey
    private static final String SQL_INSERT_KEY = "insert into oauth_token_key (token_key) values (?)";

    public JdbcTokenStore(DataSource dataSource) {
        Assert.notNull(dataSource, "DataSource required");
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @Override
    public String getTokenKey() {
        String tokenKey = null;
        try {
            tokenKey = jdbcTemplate.queryForObject(SQL_SELECT_KEY, String.class);
        } catch (EmptyResultDataAccessException e) {
        }
        if (tokenKey == null || tokenKey.trim().isEmpty()) {
            tokenKey = TokenUtil.getHexKey();
            jdbcTemplate.update(SQL_INSERT_KEY, tokenKey);
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
                List<Token> userTokens = findTokensByUserId(userId);
                if (userTokens.size() > maxToken) {
                    for (int i = 0; i < userTokens.size() - maxToken; i++) {
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
        List<Object> objects = getFieldsForUpdate(token);
        return jdbcTemplate.update(SQL_INSERT, listToArray(objects));
    }

    @Override
    public Token findToken(String userId, String access_token) {
        try {
            return jdbcTemplate.queryForObject(SQL_SELECT_BY_TOKEN, rowMapper, userId, access_token);
        } catch (EmptyResultDataAccessException e) {
        }
        return null;
    }

    @Override
    public List<Token> findTokensByUserId(String userId) {
        try {
            return jdbcTemplate.query(SQL_SELECT_BY_USER_ID, rowMapper, userId);
        } catch (EmptyResultDataAccessException e) {
        }
        return null;
    }

    @Override
    public int removeToken(String userId, String access_token) {
        return jdbcTemplate.update(SQL_DELETE, userId, access_token);
    }

    @Override
    public int removeTokensByUserId(String userId) {
        return jdbcTemplate.update(SQL_DELETE_BY_USER_ID, userId);
    }

    @Override
    public abstract String[] findRolesByUserId(String userId);

    @Override
    public abstract String[] findPermissionsByUserId(String userId);

    /**
     * 插入、修改操作的参数
     */
    private List<Object> getFieldsForUpdate(Token token) {
        List<Object> objects = new ArrayList();
        objects.add(token.getAccessToken());
        objects.add(token.getUserId());
        objects.add(token.getRefreshToken());
        objects.add(token.getExpireTime());
        return objects;
    }

    /**
     * listToArray
     */
    private Object[] listToArray(List<Object> list) {
        if (list == null) {
            return null;
        }
        Object[] objects = new Object[list.size()];
        for (int i = 0; i < list.size(); i++) {
            objects[i] = list.get(i);
        }
        return objects;
    }

    /**
     * Token结果集映射
     */
    private static class TokenRowMapper implements RowMapper<Token> {
        @Override
        public Token mapRow(ResultSet rs, int rowNum) throws SQLException {
            int token_id = rs.getInt("token_id");
            String access_token = rs.getString("access_token");
            String user_id = rs.getString("user_id");
            String refresh_token = rs.getString("refresh_token");
            Date expire_time = rs.getDate("expire_time");
            Date create_time = rs.getDate("create_time");
            Token token = new Token();
            token.setTokenId(token_id);
            token.setAccessToken(access_token);
            token.setUserId(user_id);
            token.setRefreshToken(refresh_token);
            token.setExpireTime(expire_time);
            token.setCreateTime(create_time);
            return token;
        }
    }

}
