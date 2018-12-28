package org.wf.jwtp;

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
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;

/**
 * Created by wangfan on 2018-12-27 下午 4:46.
 */
public class ApiInterceptor extends HandlerInterceptorAdapter {

    private TokenStore tokenStore;

    public ApiInterceptor() {
    }

    public ApiInterceptor(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    public TokenStore getTokenStore() {
        return tokenStore;
    }

    public void setTokenStore(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String access_token = request.getHeader("Authorization");
        if (access_token == null || access_token.trim().isEmpty()) {
            access_token = request.getParameter("access_token");
        }
        if (access_token == null || access_token.trim().isEmpty()) {
            throw new ErrorTokenException();
        }
        Token token = tokenStore.findToken(access_token);
        if (token == null) {
            throw new ErrorTokenException("token被篡改");
        }
        try {
            String subject = TokenUtil.parseToken(access_token, token.getTokenKey());
            if (!token.getUserId().equals(subject)) {
                throw new ErrorTokenException();
            }
            // 检查权限
            if (handler instanceof HandlerMethod) {
                Method method = ((HandlerMethod) handler).getMethod();
                if (method != null) {
                    if (!checkPermission(method, token) || !checkRole(method, token)) {
                        throw new UnauthorizedException();
                    }
                }
            }
        } catch (ExpiredJwtException e) {
            throw new ExpiredTokenException();
        } catch (Exception e) {
            throw new ErrorTokenException();
        }
        return super.preHandle(request, response, handler);
    }

    private boolean checkPermission(Method method, Token token) {
        RequiresPermissions annotation = method.getAnnotation(RequiresPermissions.class);
        if (annotation == null) {
            return true;
        }
        String[] requiresPermissions = annotation.value();
        Logical logical = annotation.logical();
        return SubjectUtil.hasPermission(token, requiresPermissions, logical);
    }

    private boolean checkRole(Method method, Token token) {
        RequiresRoles annotation = method.getAnnotation(RequiresRoles.class);
        if (annotation == null) {
            return true;
        }
        String[] requiresRoles = annotation.value();
        Logical logical = annotation.logical();
        return SubjectUtil.hasRole(token, requiresRoles, logical);
    }
}
