package org.wf.jwtp.perm;

import org.springframework.web.method.HandlerMethod;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Created by wangfan on 2019-01-21 下午 4:18.
 */
public class SimpleUrlPerm implements IUrlPerm {
    @Override
    public String[] getPermission(HttpServletRequest request, HttpServletResponse response, HandlerMethod handler) {
        return new String[]{request.getRequestURI()};
    }

    @Override
    public String[] getRoles(HttpServletRequest request, HttpServletResponse response, HandlerMethod handler) {
        return new String[0];
    }
}
