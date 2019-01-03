package org.wf.jwtp.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 配置属性
 * Created by wangfan on 2018-12-29 下午 2:13.
 */
@ConfigurationProperties(prefix = "jwtp")
public class JwtPermissionProperties {

    private Integer storeType;

    private String[] path;

    private String[] excludePath;

    private Integer maxToken;

    public Integer getStoreType() {
        return storeType;
    }

    public void setStoreType(Integer storeType) {
        this.storeType = storeType;
    }

    public String[] getPath() {
        return path;
    }

    public void setPath(String[] path) {
        this.path = path;
    }

    public String[] getExcludePath() {
        return excludePath;
    }

    public void setExcludePath(String[] excludePath) {
        this.excludePath = excludePath;
    }

    public Integer getMaxToken() {
        return maxToken;
    }

    public void setMaxToken(Integer maxToken) {
        this.maxToken = maxToken;
    }
}
