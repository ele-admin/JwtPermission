package com.wf.etp.authz;

import java.util.List;

/**
 * User授权接口
 * 
 * @author wangfan
 * @date 2018-1-21 下午4:30:34
 */
public interface IUserRealm {

	public boolean isUserToken(String userId, String token);

	public List<String> getUserRoles(String userId);

	public List<String> getUserPermissions(String userId);
}
