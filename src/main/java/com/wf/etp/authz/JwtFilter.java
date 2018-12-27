package com.wf.etp.authz;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class JwtFilter implements Filter {
    private List<String> excludeUrls = new ArrayList<>();

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        System.out.printf("过滤器实现");
        String authorization = request.getHeader("Authorization");
        String url = request.getRequestURI().toString();
        if (!isExclude(url)) {

        }
        filterChain.doFilter(request, response);
    }

    @Override
    public void destroy() {

    }

    private boolean isExclude(String url) {
        for (String eu : excludeUrls) {
            if (eu.startsWith(url)) {
                return true;
            }
        }
        return false;
    }
}
