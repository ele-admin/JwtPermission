package org.wf.jwtp.configuration;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.servlet.config.annotation.*;
import org.wf.jwtp.TokenInterceptor;
import org.wf.jwtp.provider.JdbcTokenStore;
import org.wf.jwtp.provider.RedisTokenStore;
import org.wf.jwtp.provider.TokenStore;

import javax.sql.DataSource;
import java.util.Collection;

/**
 * 框架配置
 * Created by wangfan on 2018-12-29 下午 2:11.
 */
@EnableConfigurationProperties(JwtPermissionProperties.class)
public class JwtPermissionConfiguration implements WebMvcConfigurer, ApplicationContextAware {
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
            Collection<StringRedisTemplate> stringRedisTemplates = applicationContext.getBeansOfType(StringRedisTemplate.class).values();
            if (stringRedisTemplates.size() > 0) {
                tokenStore = new RedisTokenStore(stringRedisTemplates.iterator().next(), dataSource);
            }
        } else if (properties.getStoreType() == 1) {  // db存储
            if (dataSource != null) {
                tokenStore = new JdbcTokenStore(dataSource);
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
        tokenStore.maxToken = properties.getMaxToken();
        tokenStore.findRolesSql = properties.getFindRolesSql();
        tokenStore.findPermissionsSql = properties.getFindPermissionsSql();
        return tokenStore;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        String[] path = properties.getPath();
        String[] excludePath = properties.getExcludePath();
        registry.addInterceptor(new TokenInterceptor(tokenStore()))
                .addPathPatterns(path)
                .excludePathPatterns(excludePath);
    }

}
