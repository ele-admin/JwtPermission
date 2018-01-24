package com.wf.etp.authz;

import java.util.List;

import com.wf.etp.authz.annotation.Logical;

/**
 * 权限检查工具类
 * 
 * @author wangfan
 * @date 2018-1-23 上午9:58:40
 */
public class PermissionUtil {
	private static volatile PermissionUtil instance;
	private static IUserRealm userRealm;
	private String userId;

	public static PermissionUtil getInstance(String userId) {
		if (instance == null) {
			synchronized (PermissionUtil.class) {
				if (instance == null) {
					instance = new PermissionUtil();
				}
			}
		}
		instance.userId = userId;
		return instance;
	}

	public void setUserRealm(IUserRealm userRealm) {
		PermissionUtil.userRealm = userRealm;
	}

	/**
	 * 检查是否有指定角色
	 * 
	 * @param roles
	 * @param logical
	 * @return
	 */
	public boolean hasRole(String[] roles, Logical logical) {
		if (userRealm == null) {
			throw new NullPointerException("userRealm is null");
		}
		boolean result = false;
		List<String> userRoles = userRealm.getUserRoles(userId);
		for (int i = 0; i < roles.length; i++) {
			result = userRoles.contains(roles[i]);
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
	public boolean hasPermission(String[] permissions, Logical logical) {
		if (userRealm == null) {
			throw new NullPointerException("userRealm is null");
		}
		boolean result = false;
		List<String> userPermissions = userRealm.getUserPermissions(userId);
		for (int i = 0; i < permissions.length; i++) {
			result = userPermissions.contains(permissions[i]);
			if (logical == (result ? Logical.OR : Logical.AND)) {
				break;
			}
		}
		return result;
	}
	
	/**
	 * 检查token是否与user匹配
	 * 
	 * @param userId
	 * @param token
	 * @return
	 */
	public boolean isUserToken(String token){
		if (userRealm == null) {
			throw new NullPointerException("userRealm is null");
		}
		return userRealm.isUserToken(userId, token);
	}
}
