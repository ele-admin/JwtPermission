package com.wf.etp.authz;

import java.util.ArrayList;
import java.util.List;

import com.wf.etp.authz.annotation.Logical;

/**
 * 权限检查工具类
 * 
 * @author wangfan
 * @date 2018-1-23 上午9:58:40
 */
public class SubjectUtil {
	private static volatile SubjectUtil instance;
	private static IUserRealm userRealm;

	public static SubjectUtil getInstance() {
		if (instance == null) {
			synchronized (SubjectUtil.class) {
				if (instance == null) {
					instance = new SubjectUtil();
				}
			}
		}
		return instance;
	}

	public void setUserRealm(IUserRealm userRealm) {
		SubjectUtil.userRealm = userRealm;
	}

	/**
	 * 检查是否有指定角色
	 * 
	 * @param roles
	 * @param logical
	 * @return
	 */
	public boolean hasRole(String userId, String[] roles, Logical logical) {
		checkUserRealm();
		boolean result = false;
		List<String> cacheRoles = userRealm.getCacheArray("etprs-" + userId);
		if (cacheRoles == null) {
			cacheRoles = new ArrayList<String>();
			List<String> userRoles = userRealm.getUserRoles(userId);
			if (userRoles != null) {
				cacheRoles.addAll(userRoles);
			}
		}
		for (int i = 0; i < roles.length; i++) {
			result = cacheRoles.contains(roles[i]);
			if (logical == (result ? Logical.OR : Logical.AND)) {
				break;
			}
		}
		return result;
	}

	/**
	 * 检查是否有指定权限
	 * 
	 * @param roles
	 * @param logical
	 * @return
	 */
	public boolean hasPermission(String userId, String[] permissions, Logical logical) {
		checkUserRealm();
		boolean result = false;
		List<String> cachePermissions = userRealm.getCacheArray("etpps-" + userId);
		if (permissions == null) {
			cachePermissions = new ArrayList<String>();
			List<String> userPermissions = userRealm.getUserPermissions(userId);
			if (userPermissions != null) {
				cachePermissions.addAll(userPermissions);
			}
		}
		for (int i = 0; i < permissions.length; i++) {
			result = cachePermissions.contains(permissions[i]);
			if (logical == (result ? Logical.OR : Logical.AND)) {
				break;
			}
		}
		return result;
	}

	/**
	 * 检查token是否有效
	 * 
	 * @param userId
	 * @param token
	 * @return
	 */
	public boolean isValidToken(String userId, String token) {
		checkUserRealm();
		List<String> tokens = userRealm.getCacheArray("etp-" + userId);
		return tokens != null && tokens.contains(token);
	}

	/**
	 * 缓存token
	 * 
	 * @param userId
	 * @param token
	 */
	public boolean setCacheToken(String userId, String token) {
		checkUserRealm();
		List<String> tokens = null;
		if (!userRealm.isSingleUser()) {
			tokens = userRealm.getCacheArray("etp-" + userId);
		}
		if (tokens == null) {
			tokens = new ArrayList<String>();
		}
		tokens.add(token);
		return userRealm.setCacheArray("etp-" + userId, tokens);
	}

	/**
	 * 主动让token失效
	 * 
	 * @param userId
	 * @return
	 */
	public boolean expireToken(String userId) {
		return userRealm.removeCache("etp-" + userId);
	}

	/**
	 * 检查userRealm
	 */
	private void checkUserRealm() {
		if (userRealm == null) {
			throw new NullPointerException("userRealm is null");
		}
	}
}
