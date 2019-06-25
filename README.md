# JwtPermission 

![JitPack](https://img.shields.io/jitpack/v/whvcse/JwtPermission.svg?style=flat-square)
![Hex.pm](https://img.shields.io/hexpm/l/plug.svg?style=flat-square)


## 简介
&emsp;基于jjwt实现的一套用于前后端分离项目的权限控制框架，用于实现基于token验证的Web权限框架。

<br>

## 导入

> SpringBoot集成示例：[easyweb-jwt](https://gitee.com/whvse/easyweb-jwt)，xml配置版集成示例：[前往查看](https://gitee.com/whvse/JwtPermission/attach_files)。

**maven方式导入：**
```xml
<project>
    <repositories>
        <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
        </repository>
    </repositories>
    
    <dependencies>
       <dependency>
          <groupId>com.github.whvcse.JwtPermission</groupId>
          <artifactId>jwt-permission</artifactId>
          <version>2.0.2</version>
       </dependency>
    </dependencies>
</project>
```

**SpringBoot项目导入：**
```xml
<project>
    <repositories>
        <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
        </repository>
    </repositories>
    
    <dependency>
      <groupId>com.github.whvcse.JwtPermission</groupId>
      <artifactId>jwtp-spring-boot-starter</artifactId>
      <version>2.0.2</version>
    </dependency>
</project>
```

**jar包方式导入：**

[jwt-permission最新jar包](https://github.com/whvcse/JwtPermission/releases)

[所依赖的jar包](https://gitee.com/whvse/JwtPermission/attach_files)

maven导入jar包，在项目根目录创建`libs`文件夹，然后pom.xml添加如下：
```
<dependency>
  <groupId>com.github.whvcse.JwtPermission</groupId>
  <artifactId>jwtp-spring-boot-starter</artifactId>
  <version>2.0.2</version>
  <systemPath>${basedir}/libs/jwt-permission.jar</systemPath>
</dependency>

<dependency>
  <groupId>com.github.whvcse.JwtPermission</groupId>
  <artifactId>jwtp-spring-boot-starter</artifactId>
  <version>2.0.2</version>
  <systemPath>${basedir}/libs/jwtp-spring-boot-starter.jar</systemPath>
</dependency>
```
依赖的包：
```
<!-- jjwt -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.10.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.10.5</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.10.5</version>
    <scope>runtime</scope>
</dependency>
```

<br>

## 用法

### 在SpringMVC中使用

```xml
<beans>
    <!-- 拦截器配置 -->
    <mvc:interceptors>
        <mvc:interceptor>
            <mvc:mapping path="/api/**" />
            <mvc:exclude-mapping path="/api/login" />
            <bean class="org.wf.jwtp.TokenInterceptor">
                <property name="tokenStore" ref="tokenStore" />
                <property name="maxToken" value="3" /> <!-- 单个用户最大token数 -->
            </bean>
        </mvc:interceptor>
    </mvc:interceptors>
    
    <!-- 这里可以选择 JdbcTokenStore 和 RedisTokenStore -->
    <bean id="tokenStore" class="org.wf.jwtp.provider.JdbcTokenStore">
        <constructor-arg name="dataSource" ref="dataSource" />
    </bean>
    
    <bean id="tokenStore" class="org.wf.jwtp.provider.RedisTokenStore">
        <constructor-arg name="redisTemplate" ref="stringRedisTemplate" />
    </bean>
</beans>
```

<br>

### 在SpringBoot中使用

&emsp;在你的`Application`类上面加入`@EnableJwtPermission`注解，在`application.properties`有如下配置可选：
```text
## 0是 redisTokenStore ，1是 jdbcTokenStore ，默认是0
jwtp.store-type=0

## 拦截路径，默认是/**
jwtp.path=/**

## 排除拦截路径，默认无
jwtp.exclude-path=/,/index,/login

## 单个用户最大token数，默认-1不限制
jwtp.max-token=10

## 日志级别设置debug可以输出详细信息
logging.level.org.wf.jwtp=DEBUG
```

<br>

### 登录签发token

```java
@RestController
public class LoginController {
    @Autowired
    private TokenStore tokenStore;
    
    @PostMapping("/login")
    public ResultMap login(String account, String password, HttpServletRequest request) {
        // 你的验证逻辑
        // ......
        // 签发token
        Token token = tokenStore.createNewToken(userId, permissions, roles);
        return ResultMap.ok("登录成功").put("access_token",token.getAccessToken());
    }
}
```

token默认过期时间是一天，设置过期时间方法（单位秒）：

```java
Token token = tokenStore.createNewToken(userId, permissions, roles, 60*60*24*30);
```

<br>

### 使用注解或代码限制权限
1.使用注解的方式：
```text
// 需要有system权限才能访问
@RequiresPermissions("system")

// 需要有system和front权限才能访问,logical可以不写,默认是AND
@RequiresPermissions(value={"system","front"}, logical=Logical.AND)

// 需要有system或者front权限才能访问
@RequiresPermissions(value={"system","front"}, logical=Logical.OR)

// 需要有admin或者user角色才能访问
@RequiresRoles(value={"admin","user"}, logical=Logical.OR)
```
> 注解只能加在Controller的方法上面。

<br>

2.使用代码的方式：
```text
//是否有system权限
SubjectUtil.hasPermission(request, "system");

//是否有system或者front权限
SubjectUtil.hasPermission(request, new String[]{"system","front"}, Logical.OR);

//是否有admin或者user角色
SubjectUtil.hasRole(request, new String[]{"admin","user"}, Logical.OR)
```

<br>

### 前端传递token
放在参数里面用`access_token`传递：
```javascript
$.get("/xxx", { access_token: token }, function(data) {

});
```
放在header里面用`Authorization`、`Bearer`传递： 
```javascript
$.ajax({
    url: "/xxx", 
    beforeSend: function(xhr) {
        xhr.setRequestHeader("Authorization", 'Bearer '+ token);
    },
    success: function(data){ }
});
```

<br>

## 注意事项
### 异常处理
&emsp;JwtPermistion在token验证失败和没有权限的时候抛出异常，框架定义了几个异常：
    
| 异常                  | 描述          | 错误信息                          |
|:----------------------|:-------------|:----------------------------------|
| ErrorTokenException   | token验证失败 | 错误信息“身份验证失败”，错误码401 |
| ExpiredTokenException | token已经过期 | 错误信息“登录已过期”，错误码402   |
| UnauthorizedException | 没有权限      | 错误信息“没有访问权限”，错误码403 |

&emsp;建议使用异常处理器来捕获异常并返回json数据给前台：

```xml
<bean id="exceptionHandler" class="com.xxx.ExceptionHandler" />
```

```java
public class ExceptionHandler implements HandlerExceptionResolver {

    @Override
    public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object obj, Exception ex) {
        if(ex instanceof TokenException){
            writerJson(response, ((TokenException) ex).getCode(), ex.getMessage());
        } else {
            writerJson(response, 500, ex.getMessage());
            ex.printStackTrace();
        }
        return new ModelAndView();
    }

    private void writerJson(HttpServletResponse response, int code, String msg) {
        response.setContentType("application/json;charset=UTF-8");
        try {
            PrintWriter out = response.getWriter();
            out.write("{\"code\":"+code+",\"msg\":\""+msg+"\"}");
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

<br>

### SpringBoot中异常处理
```java
@ControllerAdvice
public class ExceptionHandler {

    @ResponseBody
    @ExceptionHandler(Exception.class)
    public Map<String, Object> errorHandler(Exception ex) {
        Map<String, Object> map = new HashMap<>();
        // 根据不同错误获取错误信息
        if (ex instanceof TokenException) {
            map.put("code", ((TokenException) ex).getCode());
            map.put("msg", ex.getMessage());
        } else {
            map.put("code", 500);
            map.put("msg", ex.getMessage());
            ex.printStackTrace();
        }
        return map;
    }
}
```

<br>

### 主动让token失效：
```java
public class XX {
    @Autowired
    private TokenStore tokenStore;
    
    public void xx(){
        // 移除用户的某个token
        tokenStore.removeToken(userId, access_token);
        
        // 移除用户的全部token
        tokenStore.removeTokensByUserId(userId);
    }
}
```

<br>

### 更新角色和权限列表
&emsp;修改了用户的角色和权限需要同步更新框架中的角色和权限：
```java
public class XX {
    @Autowired
    private TokenStore tokenStore;
    
    public void xx(){
        // 更新用户的角色列表
        tokenStore.updateRolesByUserId(userId, roles);
        
        // 更新用户的权限列表
        tokenStore.updatePermissionsByUserId(userId, permissions);
    }
}
```

<br>

### 获取当前的用户信息
```text
Token token = SubjectUtil.getToken(request);
```   

<br>

### RedisTokenStore需要集成redis

1.SpringMvc集成Redis：
```xml
<beans>
    <bean id="poolConfig" class="redis.clients.jedis.JedisPoolConfig">
        <property name="maxIdle" value="300" />
        <property name="maxTotal" value="600" />
        <property name="maxWaitMillis" value="1000" />
        <property name="testOnBorrow" value="true" />
    </bean>
    
    <bean id="jedisConnectionFactory" class="org.springframework.data.redis.connection.jedis.JedisConnectionFactory">
        <property name="hostName" value="127.0.0.1" />
        <property name="password" value="" />
        <property name="port" value="6379" />
        <property name="poolConfig" ref="poolConfig" />
    </bean>
    
    <bean id="stringRedisTemplate" class="org.springframework.data.redis.core.StringRedisTemplate">
        <property name="connectionFactory" ref="jedisConnectionFactory" />
    </bean>
</beans>
```

<br>

2.SpringBoot集成reids：

maven添加依赖
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```
`application.properties`配置：
```text
spring.redis.host=127.0.0.1
spring.redis.database=0
```

<br>

### JdbcTokenStore需要导入SQL
&emsp;使用JdbcTokenStore需要导入SQL，需要配置dataSource。

<br>

## 联系方式
### 欢迎加入“前后端分离技术交流群”

![群二维码](https://ws1.sinaimg.cn/large/006a7GCKgy1fstbxycj1xj305k07m75h.jpg)

### 推荐
&emsp;`EasyWeb管理系统模板` 一个开箱即用的后台模板，使用简单，模板丰富，包含传统ifram版、spa单页面路由版，
[前往查看](https://easyweb.vip)。
