# JwtPermission 
[![GitHub release](https://img.shields.io/github/release/whvcse/JwtPermission.svg)](https://github.com/whvcse/JwtPermission/releases)
[![GitHub Release Date](https://img.shields.io/github/release-date/whvcse/JwtPermission.svg)](#简介)
[![JitPack](https://img.shields.io/jitpack/v/whvcse/JwtPermission.svg)](#简介)
[![Author](https://img.shields.io/badge/Author-Synchronized-ff69b4.svg)](#简介)

## 简介
   基于jjwt实现的一套用于前后端分离项目的权限管理，实现基于token验证的Java权限框架，参考shiro设计，用法与shiro相近，简单实用！
     <br/>
   可以先一看实现效果[EasyWeb](https://github.com/whvcse/EasyWeb), EasyWeb是基于此权限框架完成的一个RESTful风格、前后端分离的后端管理系统模板。 
 
  
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
    compile 'com.github.whvcse:JwtPermission:1.0.6'
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

<dependencies>
   <dependency>
      <groupId>com.github.whvcse</groupId>
      <artifactId>JwtPermission</artifactId>
      <version>1.0.6</version>
   </dependency>
</dependencies>
```
#### jar包下载
[JwtPermission-最新版本.jar](https://github.com/whvcse/JwtPermission/releases)。  
<br/>
此项目依赖于j2ee环境，spring mvc环境，jjwt包，使用jar包导入时请注意导入spring mvc、jjwt的jar包，使用maven或者grade方式导入会自动引入。 

-----
  
   
## 用法
  
### 第一步、与spring mvc集成：
此项目的全部配置均在spring mvc的配置文件中进行。 
```java
<!-- token拦截器配置 -->
<mvc:interceptors>
    <mvc:interceptor>
        <mvc:mapping path="/api/**" /> <!-- 拦截所有  -->
        <mvc:exclude-mapping path="/api/login" />  <!-- 排除登录接口 -->
        <bean class="com.wf.etp.authz.ApiInterceptor">  <!-- 框架提供的拦截器 -->
            <property name="userRealm" ref="userRealm" />  <!-- 需要提供UserRealm -->
            <property name="cache" ref="etpCache" /> <!-- 需要提供缓存实现 -->
            <property name="tokenKey" value="e-t-p" />  <!-- 生成token的key,可以不写默认是'e-t-p' -->
        </bean>
    </mvc:interceptor>
</mvc:interceptors>

<!-- 实现UserRealm -->
<bean id="userRealm" class="com.wf.ew.core.auth.UserRealm" />

<!-- 自定义缓存实现 -->
<bean id="etpCache" class="com.wf.ew.core.auth.EtpCache" />

<!-- 扫描UserRealm和EtpCache所在的包 -->
<context:component-scan base-package="com.wf.ew.core.auth" />

```
  
   
### 第二步、实现UserRealm接口和缓存接口：
#### 1.自定义UserRealm, 需要实现IUserRealm接口(IUserRealm在1.0.2版本开始改成了抽象类)
```java
import com.wf.etp.authz.IUserRealm;
import com.wf.ew.system.model.Permission;
import com.wf.ew.system.service.PermissionService;
import com.wf.ew.system.service.UserService;

public class UserRealm extends IUserRealm {
	@Autowired
	private UserService userService;
	@Autowired
	private PermissionService permissionService;

	/**
	 * 获取用户的角色
	 */
	@Override
	public Set<String> getUserRoles(String userId) {
		Set<String> roles = new HashSet<String>();
		roles.add(userService.getUserById(userId).getRoleId());
		return roles;
	}

	/**
	 * 获取用户的权限
	 */
	@Override
	public Set<String> getUserPermissions(String userId) {
		Set<String> permissionValues = new HashSet<String>();
		List<String> userRoles = SubjectUtil.getInstance().getUserRoles(userId);
		if(userRoles.size()>0){
			List<Permission> permissions = permissionService.getPermissionsByRoleId(userRoles.get(0));
			for (int i = 0; i < permissions.size(); i++) {
				permissionValues.add(permissions.get(i).getPermissionValue());
			}
		}
		return permissionValues;
	}

	/**
	 * 是否是单账号登录,如果为true,一个账号只能在一个设备使用,可以不重写此方法,默认是false
	 */
	@Override
	public boolean isSingleUser() {
		return false;
	}
}
```
   
#### 2.自定义缓存,需要实现IEtpCache, 这里演示用redis实现缓存操作
```java
import com.wf.etp.authz.IEtpCache;
import com.wf.ew.core.utils.RedisUtil;

public class EtpCache extends IEtpCache {
	@Autowired
	private RedisUtil redisUtil;

	@Override
	public List<String> getSet(String key) {
		return redisUtil.lRange(key, 0, -1);
	}
	@Override
	public boolean putSet(String key, Set<String> values) {
		return redisUtil.lLeftPushAll(key, values) > 0;
	}
	@Override
	public boolean removeSet(String key, String value) {
		return redisUtil.lRemove(key, 0, value) > 0;
	}
	@Override
	public boolean delete(String key) {
		redisUtil.delete(key);
		return true;
	}
	@Override
	public boolean delete(Collection<String> keys) {
		redisUtil.delete(keys);
		return true;
	}
	@Override
	public Set<String> keys(String pattern) {
		return redisUtil.keys(pattern);
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
    String token = SubjectUtil.getInstance().createToken(loginUser.getUserId(), DateUtil.getAppointDate(new Date(), 30));  //第二个参数是到期时间
    return ResultMap.ok("登录成功！").put("token",token).put("user", loginUser);
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
//是否有system权限
SubjectUtil.getInstance().hasPermission(userId, "system");
//是否有system或者front权限
SubjectUtil.getInstance().hasPermission(userId, new String[]{"system","front"}, Logical.OR);
//是否有admin或者user角色
SubjectUtil.getInstance().hasRole(userId, new String[]{"admin","user"}, Logical.OR)
```

-------

## 注意事项
### 一、异常处理器：
JwtPermistion会在token验证失败和没有权限的时候抛出异常，框架定义了几个异常，位于`com.wf.etp.authz.exception`包下面：
    
|  异常 | 描述 | 错误信息 |
|:----:|:----:|:----:|
| ErrorTokenException | token验证失败 | 错误信息“身份验证失败”，错误码401 |
| ExpiredTokenException | token已经过期 | 错误信息“登录已过期”，错误码401 |
|UnauthorizedException | 没有权限 | 错误信息“没有访问权限”，错误码403 |

--------

建议使用异常处理器来捕获异常并返回json数据给前台：

```java
<!-- 在spring mvc中配置 -->
<!-- 异常处理 -->
<bean id="exceptionHandler" class="com.wf.ew.core.exception.ExceptionHandler" />
```

```java
import com.wf.etp.authz.exception.EtpException;

/**
 * 统一异常处理器
 */
public class ExceptionHandler implements HandlerExceptionResolver {
	//日志输出对象
	private Logger logger = Logger.getLogger(ExceptionHandler.class);

	@Override
	public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object obj, Exception ex) {
		// 根据不同错误获取错误信息,EasyTokenPermission的异常全部都继承于EtpException,在这里可以统一处理
		if(ex instanceof EtpException){
			writerJson(response, ((EtpException) ex).getCode(), ex.getMessage());
			//ex.getMessage()返回的信息如上面表格所示,如果需要修改返回的信息和code,可以分开捕获上述表格中的每一个异常
		} else {
			writerJson(response, 500, "未知错误，请稍后再试！");
			logger.error(ex.getMessage(), ex.getCause());
		}
		return new ModelAndView();
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
			out.write("{\"code\":"+code+",\"msg\":\""+msg+"\"}");
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

//让user的某一个token失效
SubjectUtil.getInstance().expireToken(userId, token);
```
   
### 三、更新角色和权限的缓存
用户的角色和权限是在第一次调用了判断权限的方法的时候才会从数据库查询，然后永久存储在缓存中，如果管理员修改了用户的角色和权限，请不要忘记调用如下方法来更新缓存的用户角色和权限列表：
```java
//更新用户角色缓存
SubjectUtil.getInstance().updateCacheRoles(userId);
SubjectUtil.getInstance().updateCacheRoles();  //更新所有用户 
 
//更新用户权限缓存
SubjectUtil.getInstance().updateCachePermission(userId);
SubjectUtil.getInstance().updateCachePermission();  //更新所有用户 
```
   
### 四、代码获取user的角色和权限
```java
//获取角色
SubjectUtil.getInstance().getUserRoles(String userId);
//获取权限
SubjectUtil.getInstance().getUserPermissions(String userId);

```   
   
   
### 五、关于密码的md5加密处理：
上面登录接口示例中用到了EndecryptUtil来加密密码，这个工具类是我的另一个开源项目：[加密解密工具类](https://github.com/whvcse/EndecryptUtil)，包含Base64编码转换、16进制编码转换、AES加密、AES解密、Md5加密、Md5加盐加密等。 

      

### 六、关于Redis的使用：
上面示例中的RedisUtil这个工具类我也放到github上面了，大家可以去看看：[RedisUtil](https://github.com/whvcse/RedisUtil)，我在里面详细介绍了StringRedisTemplate和RedisTemplate的区别，以及如何规范的操作Redis。
       
   
  --------------
     
  
## 框架原理及流程介绍 
使用jjwt生成token，并且把userId设置为token的载体(payload)，使用spring mvc的拦截器拦截指定的controller，先从request中获取token(先getHeader，没有再getParam)，然后解析token，解析失败或者token过期抛出异常，解析成功将载体userId存入request域中，然后继续解析controller上面的自定义注解，然后判断是否有权限，通过userRealm根据userId获取对应的权限来判断，没有权限抛出异常。<br/>
注：所以controller可以直接使用request.getAttribute("userId")来获取userId，异常使用异常处理器来处理返回需要的json数据，上文有写。  
    
   
 ------------
    
## 联系方式
### 1、欢迎加入“前后端分离技术交流群”：
![群二维码](https://raw.githubusercontent.com/whvcse/EasyWeb/master/WebRoot/assets/images/images_qqgroup.png)
     <br/>
### 2、点个star再走：
如果JwtPermission帮到了你，请留下一颗小星星，非常感谢！ 
