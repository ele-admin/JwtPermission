package org.wf.jwtp.perm;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.method.HandlerMethod;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;

/**
 * Created by wangfan on 2019-01-21 下午 4:19.
 */
public class RestUrlPerm implements IUrlPerm {
    @Override
    public String[] getPermission(HttpServletRequest request, HttpServletResponse response, HandlerMethod handler) {
        String[] methodMapping = null;
        String[] requestMethod = null;
        String controllerMapping = null;
        String[] rsPermissions = new String[]{};

        Method method = handler.getMethod();
        GetMapping annotationGet = method.getAnnotation(GetMapping.class);
        if (annotationGet != null) {
            requestMethod = new String[]{"get"};
            methodMapping = annotationGet.value();
        } else {
            PostMapping annotationPost = method.getAnnotation(PostMapping.class);
            if (annotationPost != null) {
                requestMethod = new String[]{"post"};
                methodMapping = annotationPost.value();
            } else {
                PutMapping annotationPut = method.getAnnotation(PutMapping.class);
                if (annotationPut != null) {
                    requestMethod = new String[]{"put"};
                    methodMapping = annotationPut.value();
                } else {
                    DeleteMapping annotationDel = method.getAnnotation(DeleteMapping.class);
                    if (annotationDel != null) {
                        requestMethod = new String[]{"delete"};
                        methodMapping = annotationDel.value();
                    } else {
                        RequestMapping annotationReq = method.getAnnotation(RequestMapping.class);
                        if (annotationReq != null) {
                            requestMethod = new String[]{"get", "post", "put", "delete"};
                            methodMapping = annotationReq.value();
                        }
                    }
                }
            }
        }
        controllerMapping = getControllerMapping(method.getDeclaringClass());

        if (requestMethod != null) {
            for (String rM : requestMethod) {
                StringBuilder builder = new StringBuilder();
                builder.append(rM);
                builder.append(":");
                if (controllerMapping != null) {
                    if (!controllerMapping.startsWith("/")) {
                        builder.append("/");
                    }
                    builder.append(controllerMapping);
                }
                for (String mp : methodMapping) {

                }
            }
        }

        return new String[0];
    }

    @Override
    public String[] getRoles(HttpServletRequest request, HttpServletResponse response, HandlerMethod handler) {
        return new String[0];
    }

    private String getControllerMapping(Class<?> clazz) {
        String[] requestMapping = null;
        GetMapping annotationGet = clazz.getAnnotation(GetMapping.class);
        if (annotationGet != null) {
            requestMapping = annotationGet.value();
        } else {
            PostMapping annotationPost = clazz.getAnnotation(PostMapping.class);
            if (annotationPost != null) {
                requestMapping = annotationPost.value();
            } else {
                PutMapping annotationPut = clazz.getAnnotation(PutMapping.class);
                if (annotationPut != null) {
                    requestMapping = annotationPut.value();
                } else {
                    DeleteMapping annotationDel = clazz.getAnnotation(DeleteMapping.class);
                    if (annotationDel != null) {
                        requestMapping = annotationDel.value();
                    } else {
                        RequestMapping annotationReq = clazz.getAnnotation(RequestMapping.class);
                        if (annotationReq != null) {
                            requestMapping = annotationReq.value();
                        }
                    }
                }
            }
        }
        if (requestMapping != null && requestMapping.length > 0) {
            return requestMapping[0];
        }
        return null;
    }
}
