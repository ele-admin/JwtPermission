# EasyTokenPermission

## 简介
一套用于java RESTful风格服务端api的权限框架，基于jjwt实现前后端分离项目的权限管理，实现java后端基于token验证的权限框架！

  
## 导入
#### gradle方式的引入
需要先在project的build.gradle下添加：
```java
allprojects {
    repositories {
        maven { url 'https://jitpack.io' }
    }
}
```
```java
dependencies {
    compile 'com.github.whvcse:EasyTokenPermission:1.0.1'
}
```
#### maven方式引入
```java
<repositories>
    <repository>
    <id>jitpack.io</id>
    <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.github.whvcse</groupId>
    <artifactId>EasyTokenPermission</artifactId>
    <version>1.0.1</version>
</dependency>
```
#### jar包下载
[EasyTokenPermission-最新版本.jar](https://github.com/whvcse/EasyTokenPermission/releases)。  此项目依赖于j2ee环境，spring mvc环境，使用jar包导入时请注意导入spring mvc的包，使用maven或者grade方式导入会自动引入。 
     
      
## 用法
  
### 第一步、与spring mvc集成：
此项目的全部配置均在spring mvc的配置文件中进行。 
```java
<!-- token拦截器配置 -->
<mvc:interceptors>
    <mvc:interceptor>
        <mvc:mapping path="/**" /> <!-- 拦截所有  -->
        <mvc:exclude-mapping path="/login/**" />  <!-- 排除登录接口 -->
        <bean class="com.wf.etp.authz.ApiInterceptor">  <!-- 框架提供的拦截器 -->
            <property name="userRealm" ref="userRealm" />  <!-- 需要提供UserRealm -->
        </bean>
    </mvc:interceptor>
</mvc:interceptors>

<!-- 实现UserRealm -->
<bean id="userRealm" class="com.wf.ew.core.auth.UserRealm" />

<!-- 扫描UserRealm所在的包 -->
<context:component-scan base-package="com.wf.ew.core.auth" />

```
  
### 第二步、实现UserRealm接口：
```java
package com.wf.ew.core.auth;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;

import com.wf.etp.authz.IUserRealm;
import com.wf.ew.core.utils.RedisUtil;
import com.wf.ew.system.model.Permission;
import com.wf.ew.system.service.PermissionService;
import com.wf.ew.system.service.UserService;

/**
 * UserRealm需要实现IUserRealm接口
 * 
 * @author wangfan
 * @date 2018-1-22 上午8:30:17
 */
@SuppressWarnings("unchecked")
public class UserRealm implements IUserRealm {
	@Autowired
	private UserService userService;
	@Autowired
	private PermissionService permissionService;
	@Autowired
	private RedisUtil redisUtil;

	/**
	 * 获取用户的角色
	 */
	@Override
	public List<String> getUserRoles(String userId) {
		List<String> roles = new ArrayList<>();
		roles.add(userService.getUserById(userId).getRoleId());
		return roles;
	}

	/**
	 * 获取用户的权限
	 */
	@Override
	public List<String> getUserPermissions(String userId) {
		List<String> permissionValues = new ArrayList<>();
		List<Permission> permissions = permissionService.getPermissionsByRoleId(getUserRoles(userId).get(0));
		for(int i=0;i<permissions.size();i++){
			permissionValues.add(permissions.get(i).getPermissionValue());
		}
		return permissionValues;
	}

	/**
	 * 是否是单账号登录,如果为true,一个账号只能在一个设备使用
	 */
	@Override
	public boolean isSingleUser() {
		return false;
	}

	
	/** 以下三个方法是缓存的实现,这里使用redis完成缓存 */
	/**
	 * 获取缓存的list
	 */
	@Override
	public List<String> getCacheArray(String key) {
		return (List<String>) redisUtil.get(key);
	}

	/**
	 * 移除缓存
	 */
	@Override
	public boolean removeCache(String key) {
		redisUtil.remove(key);
		return true;
	}

	/**
	 * 缓存list
	 */
	@Override
	public boolean setCacheArray(String key, List<String> strs) {
		return redisUtil.set(key, strs);
	}
}
```
  
### 第三步、编写登录接口：
```java
/**
 * 登录
 */
@PostMapping("login")
public ResultMap login(String account, String password, HttpServletRequest request) {
    if(StringUtil.isBlank(account)||StringUtil.isBlank(password)){
        return ResultMap.error("账号或密码不能为空！");
    }
    User loginUser = userService.getUserByAccount(account);
    if(loginUser==null){
        return ResultMap.error("账号不存在！");
    }else if(loginUser.getUserStatus()!=0){
        return ResultMap.error("账号被锁定！");
    }else if(!EndecryptUtils.encrytMd5(password, loginUser.getUserId(), 3).equals(loginUser.getUserPassword())){
        return ResultMap.error("密码错误！");
    }
    //添加到登录日志
    addLoginRecord(request, loginUser.getUserId());
    //使用框架提供的TokenUtil生成token 
    String token = TokenUtil.createToken(loginUser.getUserId(), 1000*360*24*30);  //第二个参数是过期时间(单位s) 
    loginUser.setToken(token);
    return ResultMap.ok("登录成功！").put("user", loginUser);
}
```
  
### 第四步、使用注解或代码限制权限： 
1.使用注解的方法：
```java
/**
 * 需要有system权限才能访问
 */
@RequiresPermissions("system")
@GetMapping
public ResultMap a() {
	return ResultMap.ok();
}

/**
 * 需要有system和front权限才能访问,logical可以不写,默认是AND
 */
@RequiresPermissions(value={"system","front"}, logical=Logical.AND)
@GetMapping
public ResultMap b() {
	return ResultMap.ok();
}

/**
 * 需要有system或者front权限才能访问
 */
@RequiresPermissions(value={"system","front"}, logical=Logical.OR)
@GetMapping
public ResultMap c() {
	return ResultMap.ok();
}

/**
 * 需要有admin或者user角色才能访问
 */
@RequiresRoles(value={"admin","user"}, logical=Logical.OR)
@GetMapping
public ResultMap d() {
	return ResultMap.ok();
}
```
2.使用代码的方式：
```java
SubjectUtil.getInstance().hasPermission(userId, new String[]{"system","front"}, Logical.OR);

SubjectUtil.getInstance().hasRole(userId, new String[]{"system","front"}, Logical.OR)
```
    
    
## 注意事项
### 一、异常处理器：
EasyTokenPermistion会在token验证失败和没有权限的时候抛出异常，框架定义了几个异常(包名`com.wf.etp.authz.exception`)：
  
|  异常 | 描述 | 错误信息 |
|:----:|:----:|:----:|
| ErrorTokenException | token验证失败 | 错误信息“身份验证400”，错误码401 |
| ExpiredTokenException | token已经过期 | 错误信息“登录已过期”，错误码401 |
 |UnauthorizedException | 没有权限 | 错误信息“没有访问权限”，错误码403 |
   
所以建议使用异常处理器来捕获异常并返回json数据给前台：
```java
<!-- 在spring mvc中配置 -->
<!-- 异常处理 -->
<bean id="exceptionHandler" class="com.wf.ew.core.exception.ExceptionHandler" />
```
```java
package com.wf.ew.core.exception;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

import com.wf.etp.authz.exception.EtpException;

/**
 * 统一异常处理器
 * 
 * @author wangfan
 * @date 2017-7-14 下午3:27:35
 */
public class ExceptionHandler implements HandlerExceptionResolver {
	//日志输出对象
	private Logger logger = Logger.getLogger(ExceptionHandler.class);

	@Override
	public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object obj, Exception ex) {
		ex.printStackTrace();
		logger.error(ex.getMessage(), ex.getCause());
		// 根据不同错误获取错误信息,EasyTokenPermission的异常全部都继承于EtpException,在这里可以统一处理
		if(ex instanceof EtpException){
			writerJson(response, ((EtpException) ex).getCode(), ex.getMessage());
		} else {
			writerJson(response, 500, "未知错误，请稍后再试！");
		}
		return null;
	}

	/**
	 * 写入json数据
	 * @param response
	 * @throws Exception 
	 */
	private void writerJson(HttpServletResponse response, int code, String msg) {
		response.setContentType("application/json;charset=UTF-8");
		try {
			PrintWriter out = response.getWriter();
			out.print("{\"code\":"+code+",\"msg\":\""+msg+"\"}");
			out.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
```
  
### 二、主动让token失效：
token签发后没有到过期时间是一直有效的, 如果需要主动设置token失效, 使用下面方法：
```java
//让userId这个用户重新登录
SubjectUtil.getInstance().expireToken(userId);
```
   
### 三、关于密码的md5加密处理：
上面登录接口示例中用到了EndecryptUtil来加密密码，这个工具类是我的另一个开源项目，[加密解密工具类](https://github.com/whvcse/EndecryptUtil)，包含Base64编码转换、16进制编码转换、AES加密、AES解密、Md5加密、Md5加盐加密等。 
      
    
