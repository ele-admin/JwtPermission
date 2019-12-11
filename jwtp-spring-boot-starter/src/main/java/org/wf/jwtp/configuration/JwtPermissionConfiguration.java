package org.wf.jwtp.configuration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.config.annotation.*;
import org.wf.jwtp.TokenInterceptor;
import org.wf.jwtp.perm.RestUrlPerm;
import org.wf.jwtp.perm.SimpleUrlPerm;
import org.wf.jwtp.perm.UrlPerm;
import org.wf.jwtp.provider.TokenStore;

import javax.sql.DataSource;
import java.util.Collection;

/**
 * 框架配置
 * Created by wangfan on 2018-12-29 下午 2:11.
 */
@EnableConfigurationProperties(JwtPermissionProperties.class)
public class JwtPermissionConfiguration implements WebMvcConfigurer, ApplicationContextAware {
    protected final Log logger = LogFactory.getLog(this.getClass());
    @Autowired
    private JwtPermissionProperties properties;
    private ApplicationContext applicationContext;

    @Bean
    @ConditionalOnMissingBean
    public TokenStore tokenStore() {
        TokenStore tokenStore = null;
        // 获取数据源
        DataSource dataSource = null;
        Collection<DataSource> dataSources = applicationContext.getBeansOfType(DataSource.class).values();
        if (dataSources.size() > 0) {
            dataSource = dataSources.iterator().next();
        }
        // 判断配置的token存储类型
        if (properties.getStoreType() == 0) {  // redis存储
            Collection<org.springframework.data.redis.core.StringRedisTemplate> stringRedisTemplates = applicationContext.getBeansOfType(org.springframework.data.redis.core.StringRedisTemplate.class).values();
            if (stringRedisTemplates.size() > 0) {
                tokenStore = new org.wf.jwtp.provider.RedisTokenStore(stringRedisTemplates.iterator().next(), dataSource);
            } else {
                logger.error("StringRedisTemplate is null");
            }
        } else if (properties.getStoreType() == 1) {  // db存储
            if (dataSource != null) {
                tokenStore = new org.wf.jwtp.provider.JdbcTokenStore(dataSource);
            } else {
                logger.error("DataSource is null");
            }
        } else {  // 自定义存储
            Collection<TokenStore> tokenStores = applicationContext.getBeansOfType(TokenStore.class).values();
            while (tokenStores.iterator().hasNext()) {
                tokenStore = tokenStores.iterator().next();
                if (tokenStore != null) {
                    break;
                }
            }
        }
        // 添加配置参数
        tokenStore.setMaxToken(properties.getMaxToken());
        tokenStore.setFindRolesSql(properties.getFindRolesSql());
        tokenStore.setFindPermissionsSql(properties.getFindPermissionsSql());
        if (tokenStore == null) {
            logger.error("Unknown TokenStore");
        }
        return tokenStore;
    }

    @Bean
    @ConditionalOnMissingBean
    public UrlPerm urlPerm() {
        UrlPerm urlPerm = null;
        // 判断配置的token存储类型
        if (properties.getUrlPermType() == 0) {  // 简易模式
            urlPerm = new SimpleUrlPerm();
        } else if (properties.getUrlPermType() == 1) {  // RESTful模式
            urlPerm = new RestUrlPerm();
        } else {  // 自定义模式
            Collection<UrlPerm> urlPerms = applicationContext.getBeansOfType(UrlPerm.class).values();
            while (urlPerms.iterator().hasNext()) {
                urlPerm = urlPerms.iterator().next();
                if (urlPerm != null) {
                    break;
                }
            }
        }
        return urlPerm;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    /**
     * 添加拦截器
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        String[] path = properties.getPath();
        String[] excludePath = properties.getExcludePath();
        registry.addInterceptor(new TokenInterceptor(tokenStore(), urlPerm()))
                .addPathPatterns(path)
                .excludePathPatterns(excludePath);
    }

}
