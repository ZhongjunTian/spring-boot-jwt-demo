# spring-boot-jwt-demo
Simple demo with only 3 classes


######通常情况下, 将api直接暴露出来是非常危险的. 每一个api呼叫, 用户都应该附上额外的信息, 以供我们认证和授权. 而JWT是一种既能满足这样需求, 而又简单安全便捷的方法. 前端login获取JWT之后, 只需在每一次HTTP呼叫的时候添加上JWT作为HTTP Header即可.
本文将用不到100行Java代码, 教你如何在Spring Boot里面用JWT保护RESTful api.

源代码在 [https://github.com/ZhongjunTian/spring-boot-jwt-demo](https://github.com/ZhongjunTian/spring-boot-jwt-demo/tree/master/basic/src/main/java/basic)
打开在线demo网站[jontian.com:8080](http://jontian.com:8080) 或者代码运行之后打开[localhost:8080](http://localhost:8080), 
未登录之前点击 **Call Example Service** 返回 401 Unaothorized 错误. 
![登录前](http://upload-images.jianshu.io/upload_images/6110329-aaafc0cfeb9d297c.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
登录之后即可得到正确结果
![登陆后](http://upload-images.jianshu.io/upload_images/6110329-c5158e82d1043af6.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
***
#1. 什么是JWT
了解JWT的同学可以跳过这一部分

废话少说, 我们先看看什么是JWT. JSON Web Token其实就是一个包含认证数据的JSON, 大概长这样子
分三个部分, 
第一部分`{"alg":"HS512"}`是签名算法 
第二部分 `{"exp":1495176357,"username":"admin"}`是一些数据(你想放什么都可以), 这里有过期日期和用户
第三部分`	')4'76-DM(H6fJ::$ca4~tI2%Xd-$nL(l`非常重要,是签名Signiture, 服务器会验证这个以防伪造. 因为JWT其实是明文传送, 任何人都能篡改里面的内容. 服务端通过验证签名, 而验证这个JWT是自己生成的.

原理也不是很复杂, 我用一行代码就能表示出来
首先我们将JWT第一第二部分的内容, 加上你的秘钥(key), 然后用某个算法(比如hash算法)求一下, 求得的内容就是你的签名. 验证的时候只需要验证你用JWT算出来的值是否等于JWT里面的签名. 
因为别人没有你的key, 所以也就没法伪造签名. 
######简单粗暴一行代码解释什么是签名:
```
 int signiture = ("{alg:HS512}{exp:1495176357,username:admin}" + key).hashCode();
```
######完整的JWT:
```
{"alg":"HS512"}{"exp":1495176357,"username":"admin"}	')4'76-DM(H6fJ::$ca4~tI2%Xd-$nL(l
```
通常我们都是把JWT用base64编码之后放在http的header里面, 并且每一次呼叫api都附上这个JWT, 并且服务器每次也验证JWT是否过期
######通常我们用到的JWT:
```
Base64编码后
Bearer eyJhbGciOiJIUzUxMiJ9.eyJleHAiOjE0OTUxNzYzNTcsInVzZXJuYW1lIjoiYWRtaW4ifQ.mQtCfLKfI0J7c3HTYt7kRN4AcoixiUSDaZv2ZKOjq2JMZjBhf1DmE0Fn6PdEkyJZhYZJTMLaIPwyR-uu6BMKGw
```

***
#2. 三个class实现JWT
整个demo一共有三个class
Application.java JwtAuthenticationFilter.java 和 JwtUtil.java
####首先我们看一看Application.java

第一步创建一个hello world api
```
    @GetMapping("/protected")
    public @ResponseBody Object hellWorld() {
        return "Hello World! This is a protected api";
    }
```
第二步创建一个 login的api, 我们会验证用户的密码, 如果正确, 那么我们会生成jwt, 然后以Header的形式返回给用户. 这时前端拿到的这个jwt就类似于拿到了一个临时的密码, 之后所有的HTTP RESTful api请求都附上这个"临时密码"即可.
```
    @PostMapping("/login")
    public void login(HttpServletResponse response,
                      @RequestBody final AccountCredentials credentials) throws IOException {
        if(validCredentials(credentials)) {
            String jwt = JwtUtil.generateToken(credentials.username);
            response.addHeader(HEADER_STRING, TOKEN_PREFIX + " " + jwt);
        }else
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Wrong credentials");
    }
```
最后我们再注册一个Bean, 这个JwtAuthenticationFilter继承了OncePerRequestFilter, 任何请求都会经过我们的JwtAuthenticationFilter, 我们会在filter里面验证JWT的令牌(token).
而入参`"/*.html", "/", "/login"`是这里的排除条件, 当用户访问我们的index.html或者/login的时候并不需要令牌.
完整版[Application.java](https://github.com/ZhongjunTian/spring-boot-jwt-demo/blob/master/basic/src/main/java/basic/Application.java)
```
@Bean
    public FilterRegistrationBean jwtFilter() {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean();
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter("/*.html", "/", "/login");
        registrationBean.setFilter(filter);
        return registrationBean;
    }
```
####接着我们看一下JwtAuthenticationFilter.java
这里我们继承了OncePerRequestFilter, 保证了用户请求任何资源都会运行这个doFilterInternal. 这里我们会从HTTP Header里面截取JWT, 并且验证JWT的签名和过期时间, 如果有问题, 我们会返回HTTP 401错误. 
PS: 源代码还有一个protectUrlPattern变量, 只有符合这个模板的URL才会被保护.
完整版[JwtAuthenticationFilter.java](https://github.com/ZhongjunTian/spring-boot-jwt-demo/blob/master/basic/src/main/java/basic/JwtAuthenticationFilter.java)
```
public class JwtAuthenticationFilter extends OncePerRequestFilter {
     //......一些不重要的代码......
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
       try {
           if(pathMatcher.match(protectUrlPattern, request.getServletPath())) {
               String token = request.getHeader(HEADER_STRING);
               JwtUtil.validateToken(token);
           }
       } catch (Exception e) {
           response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
           return;
       }
       filterChain.doFilter(request, response);
    }
    //......一些不重要的代码......
}
```
####最后我们看一下JwtUtil.java
这里就两个函数, 第一个输入是用户名, 返回一个有效期3600秒的JWT
` public static String generateToken(String username) `
第二个函数是验证JWT是否有效, 如果JWT有效则返回用户名, 某种 throws Exception
` public static String validateToken(String token) `
完整版[JwtUtil.java](https://github.com/ZhongjunTian/spring-boot-jwt-demo/blob/master/basic/src/main/java/basic/JwtUtil.java)

有什么需要补充的 欢迎留言
以上
