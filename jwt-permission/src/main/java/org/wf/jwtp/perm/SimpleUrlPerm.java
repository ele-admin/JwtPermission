package org.wf.jwtp.perm;

import org.springframework.web.method.HandlerMethod;
import org.wf.jwtp.annotation.Logical;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * url自动对应权限 - 简易模式
 * Created by wangfan on 2019-01-21 下午 4:18.
 */
public class SimpleUrlPerm implements UrlPerm {

    @Override
    public UrlPermResult getPermission(HttpServletRequest request, HttpServletResponse response, HandlerMethod handler) {
        return new UrlPermResult(new String[]{request.getRequestURI()}, Logical.OR);
    }

    @Override
    public UrlPermResult getRoles(HttpServletRequest request, HttpServletResponse response, HandlerMethod handler) {
        return new UrlPermResult(new String[0], Logical.OR);
    }

}
