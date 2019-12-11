package org.wf.jwtp.util;

import org.wf.jwtp.annotation.Logical;
import org.wf.jwtp.provider.Token;

import javax.servlet.http.HttpServletRequest;

/**
 * 权限检查工具类
 * <p>
 * Created by wangfan on 2018-1-23 上午9:58:40
 */
public class SubjectUtil {
    public static final String REQUEST_TOKEN_NAME = "JWTP_TOKEN";  // request中存储token的name

    /**
     * 检查是否有指定角色
     *
     * @param token   Token
     * @param roles   角色
     * @param logical 逻辑
     * @return boolean
     */
    public static boolean hasRole(Token token, String[] roles, Logical logical) {
        if (token == null) {
            return false;
        }
        if (roles == null || roles.length <= 0) {
            return true;
        }
        boolean rs = false;
        for (int i = 0; i < roles.length; i++) {
            if (token.getRoles() != null) {
                rs = contains(token.getRoles(), roles[i]);
            }
            if (logical == (rs ? Logical.OR : Logical.AND)) {
                break;
            }
        }
        return rs;
    }

    /**
     * 检查是否有指定角色
     *
     * @param token Token
     * @param roles 角色
     * @return boolean
     */
    public static boolean hasRole(Token token, String roles) {
        return hasRole(token, new String[]{roles}, Logical.OR);
    }

    /**
     * 检查是否有指定角色
     *
     * @param request HttpServletRequest
     * @param roles   角色
     * @param logical 逻辑
     * @return boolean
     */
    public static boolean hasRole(HttpServletRequest request, String[] roles, Logical logical) {
        return hasRole(getToken(request), roles, logical);
    }

    /**
     * 检查是否有指定角色
     *
     * @param request HttpServletRequest
     * @param roles   角色
     * @return boolean
     */
    public static boolean hasRole(HttpServletRequest request, String roles) {
        return hasRole(getToken(request), new String[]{roles}, Logical.OR);
    }

    /**
     * 检查是否有指定权限
     *
     * @param token       Token
     * @param permissions 权限
     * @param logical     逻辑
     * @return boolean
     */
    public static boolean hasPermission(Token token, String[] permissions, Logical logical) {
        if (token == null) {
            return false;
        }
        if (permissions == null || permissions.length <= 0) {
            return true;
        }
        boolean rs = false;
        for (int i = 0; i < permissions.length; i++) {
            if (token.getPermissions() != null) {
                rs = contains(token.getPermissions(), permissions[i]);
            }
            if (logical == (rs ? Logical.OR : Logical.AND)) {
                break;
            }
        }
        return rs;
    }

    /**
     * 检查是否有指定权限
     *
     * @param token       Token
     * @param permissions 权限
     * @return boolean
     */
    public static boolean hasPermission(Token token, String permissions) {
        return hasPermission(token, new String[]{permissions}, Logical.OR);
    }

    /**
     * 检查是否有指定权限
     *
     * @param request     HttpServletRequest
     * @param permissions 权限
     * @param logical     逻辑
     * @return boolean
     */
    public static boolean hasPermission(HttpServletRequest request, String[] permissions, Logical logical) {
        return hasPermission(getToken(request), permissions, logical);
    }

    /**
     * 检查是否有指定权限
     *
     * @param request     HttpServletRequest
     * @param permissions 权限
     * @return boolean
     */
    public static boolean hasPermission(HttpServletRequest request, String permissions) {
        return hasPermission(getToken(request), new String[]{permissions}, Logical.OR);
    }

    /**
     * 从request中获取token
     *
     * @param request HttpServletRequest
     * @return Token
     */
    public static Token getToken(HttpServletRequest request) {
        Object token = request.getAttribute(REQUEST_TOKEN_NAME);
        return token == null ? null : (Token) token;
    }

    /**
     * 判断数组是否包含指定元素
     *
     * @param strs 数组
     * @param str  元素
     * @return boolean
     */
    private static boolean contains(String[] strs, String str) {
        for (int i = 0; i < strs.length; i++) {
            if (strs[i].equals(str)) {
                return true;
            }
        }
        return false;
    }
}
