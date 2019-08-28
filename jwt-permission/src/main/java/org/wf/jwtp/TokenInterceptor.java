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
import org.wf.jwtp.provider.Config;
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
        // 放行options请求
        if (request.getMethod().equals("OPTIONS")) {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS, DELETE");
            response.setHeader("Access-Control-Max-Age", "3600");
            response.setHeader("Access-Control-Allow-Headers", "Content-Type, x-requested-with, X-Custom-Header, Authorization");
            return false;
        }
        // 判断是否忽略
        if (handler instanceof HandlerMethod) {
            Method method = ((HandlerMethod) handler).getMethod();
            if (method != null) {
                if (checkIgnore(method)){
                    logger.debug("此请求被@ignore注解，已经放行");
                    return super.preHandle(request, response, handler);
                }
            }
        }
        String access_token = request.getParameter("access_token");
        if (access_token == null || access_token.trim().isEmpty()) {
            access_token = request.getHeader("Authorization");
            if (access_token != null && access_token.length() >= 7) {
                access_token = access_token.substring(7);
            }
        }
        if (access_token == null || access_token.trim().isEmpty()) {
            throw new ErrorTokenException("token不能为空");
        }
        String subject;
        try {
            String tokenKey = tokenStore.getTokenKey();
            logger.debug("-------------------------------------------");
            logger.debug("开始解析token：" + access_token);
            logger.debug("使用tokenKey：" + tokenKey);
            subject = TokenUtil.parseToken(access_token, tokenKey);
        } catch (ExpiredJwtException e) {
            logger.debug("token已过期");
            throw new ExpiredTokenException();
        } catch (Exception e) {
            logger.debug(e.getMessage());
            throw new ErrorTokenException();
        }
        Token token = tokenStore.findToken(subject, access_token);
        if (token == null) {
            logger.debug("token不在系统中");
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
        request.setAttribute(SubjectUtil.REQUEST_TOKEN_NAME, token);
        logger.debug("-------------------------------------------");
        return super.preHandle(request, response, handler);
    }

    private boolean checkIgnore(Method method){
        Ignore annotation = method.getAnnotation(Ignore.class);
        if (annotation != null) {
           return true;
        } else {
            annotation = method.getDeclaringClass().getAnnotation(Ignore.class);
            if (annotation != null) {
                return true;
            }
        }
        return false;
    }

    private boolean checkPermission(Method method, Token token) {
        RequiresPermissions annotation = method.getAnnotation(RequiresPermissions.class);
        if (annotation == null) {
            annotation = method.getDeclaringClass().getAnnotation(RequiresPermissions.class);
            if (annotation == null) {
                return true;
            }
        }
        String[] requiresPermissions = annotation.value();
        Logical logical = annotation.logical();
        return SubjectUtil.hasPermission(token, requiresPermissions, logical);
    }

    private boolean checkRole(Method method, Token token) {
        RequiresRoles annotation = method.getAnnotation(RequiresRoles.class);
        if (annotation == null) {
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
