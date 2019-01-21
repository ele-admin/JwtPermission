package org.wf.jwtp.perm;

import org.springframework.web.method.HandlerMethod;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface IUrlPerm {

    String[] getPermission(HttpServletRequest request, HttpServletResponse response, HandlerMethod handler);

    String[] getRoles(HttpServletRequest request, HttpServletResponse response, HandlerMethod handler);
}
