package org.wf.jwtp.provider;

/**
 * 配置参数
 * Created by wangfan on 2019-01-02 上午 11:02.
 */
public class Config {
    private static volatile Config instance;
    private Integer maxToken;  // 用户最大token数

    private Config() {
    }

    public static Config getInstance() {
        if (instance == null) {
            synchronized (Config.class) {
                if (instance == null) {
                    instance = new Config();
                }
            }
        }
        return instance;
    }

    public Integer getMaxToken() {
        if (maxToken == null) {
            return -1;
        }
        return maxToken;
    }

    public void setMaxToken(Integer maxToken) {
        this.maxToken = maxToken;
    }
}
