请先阅读上一部分
[Spring Boot用3个class轻松实现JWT, 保护你的RESTful API](http://www.jianshu.com/p/e62af4a217eb)

在上一篇文章里面. 我们用JWT实现了认证Authentication. 这一篇文章我们将用JWT实现完整版的授权机制Authorization.
完整可运行代码 https://github.com/ZhongjunTian/spring-boot-jwt-demo/tree/master/complete;
运行后打开 http://localhost:8080 即可测试

授权的方法有很多种, 无非就是通过ID和Role来区分用户. 因为JWT的灵活性, 于是我们可以把用户ID放到jwt里面. 因为用户呼叫我们的api都会附带上JWT, 也就相当于直接附带上了用户ID.

###将用户ID放进jwt
当然实现起来也很简单, 我们只需要在生成JWT之前, 用 key-value的形式添加进JWT的claims就行. 比如 `map.put("userId","1"); map.put("role","admin");`. 我这里的demo就象征性的放了一个("userId", "admin")进去.

```
public static String generateToken(String id) {
        HashMap<String, Object> map = new HashMap<>();
        //you can put any data in the map
        map.put("userId", id);
        ... 一些不重要的代码 ...
        String jwt = Jwts.builder()
                .setClaims(map)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();
        return jwt;
    }
```
之后就能得到这样的jwt
```
生成的jwt:
eyJhbGciOiJIUzUxMiJ9.eyJleHAiOjE1MjAyODQ2NDEsInVzZXJJZCI6ImFkbWluIn0.ckcDMFWWYh8QOSYGxbOGZywSebWpXjF4mZOX2eWEycMb7BT7tHh8EjWSCC5EZLqKggY1uBuhpq8EvVE-Tzl7fw
Base64解码后:
{"alg":"HS512"}{"exp":1520284641,"userId":"admin"}eIlmjW^&dya2p>d.ni/TD
```
###将解码JWT后的ID放进header
我们在JWT里面添加的userId使用起来非常不方便, 因为在RestController那里只能拿到原始的JWT字符串, 需要额外的代码才能读取里面的内容. 
我们希望RestController能够直接轻易的拿到JWT里面我们放的内容. 这里有个很巧妙的办法, 在验证jwt的同时, 把解码得到的ID放进请求HttpSevletRequest的Header里面. 相当于添加了一个Header "userId" : "admin". 这样的话RestController里面使用这个Header就像下面的例子一样简单, 当成普通的header用就行. 验证JWT的代码已经帮你把脏活累活干完了.
```
    @GetMapping("/api/protected")
    public @ResponseBody Object hellWorld(@RequestHeader(value = USER_ID) String userId) {
        return "Hello World! This is a protected api, your use id is "+userId;
    }
```
![](http://upload-images.jianshu.io/upload_images/6110329-336a41171ba7f0d4.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
把userId放进HttpServletRequest用的方法比较巧妙, 需要在验证了JWT之后, 把原来的HttpServletRequest替换成我们封装后的.
```
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        ... 
            if(pathMatcher.match(protectUrlPattern, request.getServletPath())) {
                //在这里替换了原有的request
                request = JwtUtil.validateTokenAndAddUserIdToHeader(request);
            }
        ... 
        filterChain.doFilter(request, response);
    }
...
}

public class JwtUtil {
    public static HttpServletRequest validateTokenAndAddUserIdToHeader(HttpServletRequest request) {
        String token = request.getHeader(HEADER_STRING);
            // parse the token.
            Map<String, Object> body = Jwts.parser()
                        .setSigningKey(SECRET)
                        .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                        .getBody();
            String userId = (String) body.get(USER_ID);
            //下面这行代码很关键， 通过CustomHttpServletRequest实现了修改Request
            return new CustomHttpServletRequest(request, EncryptUtil.decrypt(userId));
            ... 
    }
...
}
```

###修改HttpServletRquest的方法:
把ID注入到HttpServletRquest的实现方法是继承HttpServletRequestWrapper, 重写getHeaders方法. 这样spring web框架呼叫getHeaders("userId") 就能得到这个值
```
public static class CustomHttpServletRequest extends HttpServletRequestWrapper {
        private String userId;

        public CustomHttpServletRequest(HttpServletRequest request, String userId) {
            super(request);
            this.userId = userId;
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            if (name != null && (name.equals(USER_ID))) {
                return Collections.enumeration(Arrays.asList(userId));
            }
            return super.getHeaders(name);
        }
    }
```
最后运行效果就是这样, api就能从jwt中知道用户的id是多少
![](http://upload-images.jianshu.io/upload_images/6110329-afe733b86fe4c71f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

