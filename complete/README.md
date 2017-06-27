请先阅读上一部分
[Spring Boot用3个class轻松实现JWT, 保护你的RESTful API](http://www.jianshu.com/p/e62af4a217eb)

在上一篇文章里面. 我们用JWT实现了认证Authentication. 这一篇文章我们将用JWT实现完整版的授权机制Authorization.
完整可运行代码 https://github.com/ZhongjunTian/spring-boot-jwt-demo/tree/master/complete;
运行后打开 http://localhost:8080 即可测试

授权的方法有很多种, 无非就是通过ID和Role来区分用户. 因为JWT的灵活性, 于是我们可以把用户ID放到jwt里面. 因为用户呼叫我们的api都会附带上JWT, 也就相当于直接附带上了用户ID.

当然实现起来也很简单, 我们只需要在生成JWT之前, 用 key-value的形式添加进JWT的claims就行. 比如 `map.put("id","1"); map.put("role","admin");`. 我这里的demo就象征性的放了一个("userId", "admin")进去.

当然我们不会傻乎乎的把id这么重要的信息暴露给用户, 于是我就加了个密.
```
public static String generateToken(String userId) {
        HashMap<String, Object> map = new HashMap<>();
        //you can put any data in the map
        map.put(USER_ID, EncryptUtil.encrypt(userId));
        ... 一些不重要的代码 ...
        String jwt = Jwts.builder()
                .setClaims(map)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();
        return jwt;
    }
```
加密之后的jwt就是这样的, userId和签名都是一堆乱码了.
```
{"alg":"HS512"}{"exp":1498430679,"userId":"õsXÂ±ÅÌÓïÏ\u000BÊm"}bs헂gҝ}KD辋-숔%ﻊ꙽v&<┮D̏0牶gړZ랬ǉqɻ䠄㌀
```

当我们验证JWT的时候就顺便把id给提出来,解密之后我直接简单粗暴的把数据强行塞进了HttpServletRequest. 这样能让RestController更简单粗暴的使用这个ID.
```
    public static HttpServletRequest validateTokenAndAddUserIdToHeader(HttpServletRequest request) {
        String token = request.getHeader(HEADER_STRING);
        if (token != null) {
            // parse the token.
            try {
                Map<String, Object> body = Jwts.parser()
                        .setSigningKey(SECRET)
                        .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                        .getBody();
                String userId = (String) body.get(USER_ID);
                return new CustomHttpServletRequest(request, EncryptUtil.decrypt(userId));
            } 
            ... 一些不重要的代码 ...
        } else {
        ... 一些不重要的代码 ...
        }
    }
```

RestController里面使用这个注入的Header很简单. 当成普通的header用就行. 验证JWT的代码已经帮你把脏活累活干完了.
![](http://upload-images.jianshu.io/upload_images/6110329-336a41171ba7f0d4.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
```
    @GetMapping("/api/protected")
    public @ResponseBody Object hellWorld(@RequestHeader(value = USER_ID) String userId) {
        return "Hello World! This is a protected api, your use id is "+userId;
    }
```


把ID注入到HttpServletRquest的实现方法是继承HttpServletRequestWrapper, 重写getHeaders方法. 这样userId就成了一个header.
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
