package org.wf.jwtp.provider;

import java.util.List;

/**
 * 操作token的接口
 * Created by wangfan on 2018-12-28 上午 9:21.
 */
public interface TokenStore {
    int maxToken = -1;

    /**
     * 获取生成token用的key
     *
     * @return
     */
    String getTokenKey();

    /**
     * 创建新的token
     *
     * @param userId 用户id
     * @return
     */
    Token createNewToken(String userId);

    /**
     * 创建新的token
     *
     * @param userId 用户id
     * @param expire 过期时间,单位秒
     * @return
     */
    Token createNewToken(String userId, long expire);

    /**
     * 保存Token
     *
     * @param token
     * @return
     */
    int storeToken(Token token);

    /**
     * 查询用户的某个token
     *
     * @param userId       用户id
     * @param access_token
     * @return
     */
    Token findToken(String userId, String access_token);

    /**
     * 查询用户的全部token
     *
     * @param userId 用户id
     * @return
     */
    List<Token> findTokensByUserId(String userId);

    /**
     * 移除用户的某个token
     *
     * @param userId       用户id
     * @param access_token
     * @return
     */
    int removeToken(String userId, String access_token);

    /**
     * 移除用户的全部token
     *
     * @param userId 用户id
     * @return
     */
    int removeTokensByUserId(String userId);

    /**
     * 查询用户的角色列表
     *
     * @param userId 用户id
     * @return
     */
    String[] findRolesByUserId(String userId);

    /**
     * 查询用户的权限列表
     *
     * @param userId 用户id
     * @return
     */
    String[] findPermissionsByUserId(String userId);

}
