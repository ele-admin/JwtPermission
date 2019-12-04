package org.wf.jwtp;

import io.jsonwebtoken.ExpiredJwtException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import org.wf.jwtp.annotation.Ignore;
import org.wf.jwtp.annotation.Logical;
import org.wf.jwtp.annotation.RequiresPermissions;
import org.wf.jwtp.annotation.RequiresRoles;
import org.wf.jwtp.exception.ErrorTokenException;
import org.wf.jwtp.exception.ExpiredTokenException;
import org.wf.jwtp.exception.UnauthorizedException;
import org.wf.jwtp.provider.Token;
import org.wf.jwtp.provider.TokenStore;
import org.wf.jwtp.util.SubjectUtil;
import org.wf.jwtp.util.TokenUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;

/**
 * 拦截器
 * Created by wangfan on 2018-12-27 下午 4:46.
 */
public class TokenInterceptor extends HandlerInterceptorAdapter {
    protected final Log logger = LogFactory.getLog(this.getClass());
    private TokenStore tokenStore;

    public TokenInterceptor() {
    }

    public TokenInterceptor(TokenStore tokenStore) {
        setTokenStore(tokenStore);
    }

    public TokenStore getTokenStore() {
        return tokenStore;
    }

    public void setTokenStore(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 放行options请求
        if (request.getMethod().equals("OPTIONS")) {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS, DELETE");
            response.setHeader("Access-Control-Max-Age", "3600");
            response.setHeader("Access-Control-Allow-Headers", "Content-Type, x-requested-with, X-Custom-Header, Authorization");
            return false;
        }
        Method method = null;
        if (handler instanceof HandlerMethod) {
            method = ((HandlerMethod) handler).getMethod();
        }
        // 检查是否忽略权限验证
        if (method != null && checkIgnore(method)) {
            return super.preHandle(request, response, handler);
        }
        // 获取token
        String access_token = request.getParameter("access_token");
        if (access_token == null || access_token.trim().isEmpty()) {
            access_token = request.getHeader("Authorization");
            if (access_token != null && access_token.length() >= 7) {
                access_token = access_token.substring(7);
            }
        }
        if (access_token == null || access_token.trim().isEmpty()) {
            throw new ErrorTokenException("Token不能为空");
        }
        String userId;
        try {
            String tokenKey = tokenStore.getTokenKey();
            logger.debug("ACCESS_TOKEN: " + access_token + "   TOKEN_KEY: " + tokenKey);
            userId = TokenUtil.parseToken(access_token, tokenKey);
        } catch (ExpiredJwtException e) {
            logger.debug("ERROR: ExpiredJwtException");
            throw new ExpiredTokenException();
        } catch (Exception e) {
            logger.debug("ERROR: " + e.getMessage());
            throw new ErrorTokenException();
        }
        // 检查token是否存在系统中
        Token token = tokenStore.findToken(userId, access_token);
        if (token == null) {
            throw new ErrorTokenException();
        }
        // 查询用户的权限和角色
        token.setPermissions(tokenStore.findPermissionsByUserId(userId));
        token.setPermissions(tokenStore.findRolesByUserId(userId));
        // 检查权限
        if (method != null && (!checkPermission(method, token) || !checkRole(method, token))) {
            throw new UnauthorizedException();
        }
        request.setAttribute(SubjectUtil.REQUEST_TOKEN_NAME, token);
        return super.preHandle(request, response, handler);
    }

    /**
     * 检查是否忽略权限
     */
    private boolean checkIgnore(Method method) {
        Ignore annotation = method.getAnnotation(Ignore.class);
        if (annotation == null) {  // 方法上没有注解再检查类上面有没有注解
            annotation = method.getDeclaringClass().getAnnotation(Ignore.class);
            if (annotation == null) {
                return false;
            }
        }
        return true;
    }

    /**
     * 检查权限是否符合
     */
    private boolean checkPermission(Method method, Token token) {
        RequiresPermissions annotation = method.getAnnotation(RequiresPermissions.class);
        if (annotation == null) {  // 方法上没有注解再检查类上面有没有注解
            annotation = method.getDeclaringClass().getAnnotation(RequiresPermissions.class);
            if (annotation == null) {
                return true;
            }
        }
        String[] requiresPermissions = annotation.value();
        Logical logical = annotation.logical();
        return SubjectUtil.hasPermission(token, requiresPermissions, logical);
    }

    /**
     * 检查角色是否符合
     */
    private boolean checkRole(Method method, Token token) {
        RequiresRoles annotation = method.getAnnotation(RequiresRoles.class);
        if (annotation == null) {  // 方法上没有注解再检查类上面有没有注解
            annotation = method.getDeclaringClass().getAnnotation(RequiresRoles.class);
            if (annotation == null) {
                return true;
            }
        }
        String[] requiresRoles = annotation.value();
        Logical logical = annotation.logical();
        return SubjectUtil.hasRole(token, requiresRoles, logical);
    }

}
