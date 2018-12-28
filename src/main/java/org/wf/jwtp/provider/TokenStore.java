package org.wf.jwtp.provider;

import java.util.List;

/**
 * Created by wangfan on 2018-12-28 上午 9:21.
 */
public interface TokenStore {

    int storeToken(Token token);

    Token findToken(String access_token);

    List<Token> findTokensByUserId(String userId);

    int removeToken(String access_token);

    int removeTokensByUserId(String userId);

    int updateRolesByUserId(String userId, String[] roles);

    int updatePermissionsByUserId(String userId, String[] permissions);
}
