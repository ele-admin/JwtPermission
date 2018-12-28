package org.wf.jwtp.util;

import org.wf.jwtp.provider.Token;

import javax.servlet.http.HttpServletRequest;

import org.wf.jwtp.annotation.Logical;

/**
 * 权限检查工具类
 *
 * @author WangFan
 * @date 2018-1-23 上午9:58:40
 */
public class SubjectUtil {

    /**
     * 检查是否有指定角色
     *
     * @param token
     * @param roles
     * @param logical
     * @return
     */
    public static boolean hasRole(Token token, String[] roles, Logical logical) {
        if (token == null) {
            return false;
        }
        boolean rs = false;
        for (int i = 0; i < roles.length; i++) {
            if (token.getRoles() != null) {
                rs = token.getRoles().contains(roles[i]);
            }
            if (logical == (rs ? Logical.OR : Logical.AND)) {
                break;
            }
        }
        return rs;
    }

    public static boolean hasRole(Token token, String roles) {
        return hasRole(token, new String[]{roles}, Logical.OR);
    }

    public static boolean hasRole(HttpServletRequest request, String[] roles, Logical logical) {
        return hasRole(getToken(request), roles, logical);
    }

    public static boolean hasRole(HttpServletRequest request, String roles) {
        return hasRole(getToken(request), new String[]{roles}, Logical.OR);
    }

    /**
     * 检查是否有指定权限
     *
     * @param token
     * @param permissions
     * @param logical
     * @return
     */
    public static boolean hasPermission(Token token, String[] permissions, Logical logical) {
        if (token == null) {
            return false;
        }
        boolean rs = false;
        for (int i = 0; i < permissions.length; i++) {
            if (token.getPermissions() != null) {
                rs = token.getPermissions().contains(permissions[i]);
            }
            if (logical == (rs ? Logical.OR : Logical.AND)) {
                break;
            }
        }
        return rs;
    }

    public static boolean hasPermission(Token token, String permissions) {
        return hasPermission(token, new String[]{permissions}, Logical.OR);
    }

    public static boolean hasPermission(HttpServletRequest request, String[] permissions, Logical logical) {
        return hasPermission(getToken(request), permissions, logical);
    }

    public static boolean hasPermission(HttpServletRequest request, String permissions) {
        return hasPermission(getToken(request), new String[]{permissions}, Logical.OR);
    }

    /**
     * 从request中获取token
     *
     * @param request
     * @return
     */
    public static Token getToken(HttpServletRequest request) {
        return (Token) request.getAttribute("");
    }

}
