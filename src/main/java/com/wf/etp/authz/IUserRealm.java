package com.wf.etp.authz;

import java.util.List;
import java.util.Set;

/**
 * User授权接口
 * 
 * @author wangfan
 * @date 2018-1-21 下午4:30:34
 */
public abstract class IUserRealm {

	/**
	 * 获取用户角色
	 * 
	 * @param userId
	 * @return
	 */
	public abstract Set<String> getUserRoles(String userId);

	/**
	 * 获取用户权限
	 * 
	 * @param userId
	 * @return
	 */
	public abstract Set<String> getUserPermissions(String userId);

	/**
	 * 是否是单账号登录
	 * 
	 * @return
	 */
	public boolean isSingleUser() {
		return false;
	}

	/**
	 * 获取缓存的集合
	 * 
	 * @param key
	 * @return
	 */
	public abstract List<String> getCacheSet(String key);

	/**
	 * 把集合加入缓存
	 * 
	 * @param key
	 * @param values
	 * @return
	 */
	public abstract boolean putCacheInSet(String key, Set<String> values);

	/**
	 * 清除缓存
	 * 
	 * @param key
	 * @return
	 */
	public abstract boolean clearCacheSet(String key);
}
