package org.wf.jwtp.provider;

import java.util.List;

/**
 * 操作token的接口
 * Created by wangfan on 2018-12-28 上午 9:21.
 */
public abstract class TokenStore {
    public int maxToken = -1;  // 单个用户最大的token数量
    public String findRolesSql = null;  // 查询用户角色的sql
    public String findPermissionsSql = null;  // 查询用户权限的sql

    /**
     * 获取生成token用的key
     *
     * @return
     */
    abstract String getTokenKey();

    /**
     * 创建新的token
     *
     * @param userId 用户id
     * @return
     */
    abstract Token createNewToken(String userId);

    /**
     * 创建新的token
     *
     * @param userId 用户id
     * @param expire 过期时间,单位秒
     * @return
     */
    abstract Token createNewToken(String userId, long expire);

    /**
     * 创建新的token
     *
     * @param userId      用户id
     * @param permissions 权限
     * @param roles       角色
     * @return
     */
    abstract Token createNewToken(String userId, String[] permissions, String[] roles);

    /**
     * 创建新的token
     *
     * @param userId      用户id
     * @param permissions 权限
     * @param roles       角色
     * @param expire      过期时间,单位秒
     * @return
     */
    abstract Token createNewToken(String userId, String[] permissions, String[] roles, long expire);

    /**
     * 保存Token
     *
     * @param token
     * @return
     */
    abstract int storeToken(Token token);

    /**
     * 查询用户的某个token
     *
     * @param userId       用户id
     * @param access_token
     * @return
     */
    abstract Token findToken(String userId, String access_token);

    /**
     * 查询用户的全部token
     *
     * @param userId 用户id
     * @return
     */
    abstract List<Token> findTokensByUserId(String userId);

    /**
     * 移除用户的某个token
     *
     * @param userId       用户id
     * @param access_token
     * @return
     */
    abstract int removeToken(String userId, String access_token);

    /**
     * 移除用户的全部token
     *
     * @param userId 用户id
     * @return
     */
    abstract int removeTokensByUserId(String userId);

    /**
     * 修改某个用户的角色
     *
     * @param userId 用户id
     * @param roles  角色
     * @return
     */
    abstract int updateRolesByUserId(String userId, String[] roles);

    /**
     * 修改某个用户的权限
     *
     * @param userId      用户id
     * @param permissions 权限
     * @return
     */
    abstract int updatePermissionsByUserId(String userId, String[] permissions);

    /**
     * 查询用户的角色列表
     *
     * @param userId 用户id
     * @return
     */
    abstract String[] findRolesByUserId(String userId, Token token);

    /**
     * 查询用户的权限列表
     *
     * @param userId 用户id
     * @return
     */
    abstract String[] findPermissionsByUserId(String userId, Token token);

}
