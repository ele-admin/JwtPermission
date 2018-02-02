package com.wf.etp.authz;

import java.lang.reflect.Method;

import io.jsonwebtoken.ExpiredJwtException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import com.wf.etp.authz.annotation.Logical;
import com.wf.etp.authz.annotation.RequiresPermissions;
import com.wf.etp.authz.annotation.RequiresRoles;
import com.wf.etp.authz.exception.ErrorTokenException;
import com.wf.etp.authz.exception.ExpiredTokenException;
import com.wf.etp.authz.exception.UnauthorizedException;

/**
 * 处理基于token请求的拦截器
 * 
 * @author wangfan
 * @date 2017-7-17 上午8:55:20
 */
public class ApiInterceptor implements HandlerInterceptor {

	public void setUserRealm(IUserRealm userRealm) {
		SubjectUtil.getInstance().setUserRealm(userRealm);
	}

	public void setTokenKey(String tokenKey) {
		SubjectUtil.getInstance().setTokenKey(tokenKey);
	}

	public void setCache(IEtpCache cache) {
		SubjectUtil.getInstance().setCache(cache);
	}

	@Override
	public void afterCompletion(HttpServletRequest request,
			HttpServletResponse response, Object handler, Exception ex)
			throws Exception {
	}

	@Override
	public void postHandle(HttpServletRequest request,
			HttpServletResponse response, Object handler,
			ModelAndView modelAndView) throws Exception {
	}

	@Override
	public boolean preHandle(HttpServletRequest request,
			HttpServletResponse response, Object handler) throws Exception {
		String userId = null;
		String token = request.getHeader("token");
		if (token == null) {
			token = request.getParameter("token");
		}
		try { // 解析token
			userId = SubjectUtil.getInstance().parseToken(token).getSubject();
		} catch (ExpiredJwtException e) {
			SubjectUtil.getInstance().expireToken(userId, token); // 从缓存中移除过期的token
			throw new ExpiredTokenException();
		} catch (Exception e) {
			throw new ErrorTokenException();
		}
		// 校验服务器是否存在token
		if (!SubjectUtil.getInstance().isValidToken(userId, token)) {
			throw new ExpiredTokenException();
		}
		// 检查权限
		if (handler instanceof HandlerMethod) {
			Method method = ((HandlerMethod) handler).getMethod();
			if (method != null) {
				if (!checkPermission(method, userId)
						|| !checkRole(method, userId)) {
					throw new UnauthorizedException();
				}
			}
		}
		request.setAttribute("userId", userId);
		return true;
	}

	/**
	 * 检查权限
	 * 
	 * @param method
	 * @param userId
	 * @return
	 */
	private boolean checkPermission(Method method, String userId) {
		RequiresPermissions annotation = method
				.getAnnotation(RequiresPermissions.class);
		if (annotation == null) {
			return true;
		}
		String[] requiresPermissions = annotation.value();
		Logical logical = annotation.logical();
		return SubjectUtil.getInstance().hasPermission(userId,
				requiresPermissions, logical);
	}

	/**
	 * 检查角色
	 * 
	 * @param method
	 * @param userId
	 * @return
	 */
	private boolean checkRole(Method method, String userId) {
		RequiresRoles annotation = method.getAnnotation(RequiresRoles.class);
		if (annotation == null) {
			return true;
		}
		String[] requiresRoles = annotation.value();
		Logical logical = annotation.logical();
		return SubjectUtil.getInstance()
				.hasRole(userId, requiresRoles, logical);
	}
}