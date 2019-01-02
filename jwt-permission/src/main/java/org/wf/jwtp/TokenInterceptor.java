package org.wf.jwtp;

import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import org.wf.jwtp.annotation.Logical;
import org.wf.jwtp.annotation.RequiresPermissions;
import org.wf.jwtp.annotation.RequiresRoles;
import org.wf.jwtp.exception.ErrorTokenException;
import org.wf.jwtp.exception.ExpiredTokenException;
import org.wf.jwtp.exception.UnauthorizedException;
import org.wf.jwtp.provider.Config;
import org.wf.jwtp.provider.Token;
import org.wf.jwtp.provider.TokenStore;
import org.wf.jwtp.util.SubjectUtil;
import org.wf.jwtp.util.TokenUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;

/**
 * Created by wangfan on 2018-12-27 下午 4:46.
 */
public class TokenInterceptor extends HandlerInterceptorAdapter {

    private TokenStore tokenStore;

    private Integer maxToken;

    public TokenInterceptor() {
        this(null);
    }

    public TokenInterceptor(TokenStore tokenStore) {
        this(tokenStore, -1);
    }

    public TokenInterceptor(TokenStore tokenStore, Integer maxToken) {
        setTokenStore(tokenStore);
        setMaxToken(maxToken);
    }

    public TokenStore getTokenStore() {
        return tokenStore;
    }

    public void setTokenStore(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    public Integer getMaxToken() {
        return maxToken;
    }

    public void setMaxToken(Integer maxToken) {
        this.maxToken = maxToken;
        Config.getInstance().setMaxToken(maxToken);
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String access_token = request.getParameter("access_token");
        if (access_token == null || access_token.trim().isEmpty()) {
            access_token = request.getHeader("Authorization");
            if (access_token != null && access_token.length() >= 7) {
                access_token = access_token.substring(7);
            }
        }
        if (access_token == null || access_token.trim().isEmpty()) {
            throw new ErrorTokenException();
        }
        Token token = tokenStore.findToken(access_token);
        if (token == null) {
            throw new ErrorTokenException();
        }
        try {
            String subject = TokenUtil.parseToken(access_token, token.getTokenKey());
            if (!token.getUserId().equals(subject)) {
                throw new ErrorTokenException("token被篡改");
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
            request.setAttribute(SubjectUtil.REQUEST_TOKEN_NAME, token);
        } catch (ExpiredJwtException e) {
            tokenStore.removeToken(token.getUserId(), access_token);
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
