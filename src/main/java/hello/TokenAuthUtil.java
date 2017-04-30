package hello;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class TokenAuthUtil {
    static final long EXPIRATION_TIME = 3600_000; // 1 hour
    static final String SECRET = "ThisIsASecret";
    static final String TOKEN_PREFIX = "Bearer";
    static final String HEADER_STRING = "Authorization";

    public static void addTokenToHeader(HttpServletResponse res, String username) {
        HashMap<String, Object> map = new HashMap<>();
        //you can put any data in the map
        map.put("username", username);
        String JWT = Jwts.builder()
                .setClaims(map)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();
        res.addHeader(HEADER_STRING, TOKEN_PREFIX + " " + JWT);
    }

    public static String parseToken(HttpServletRequest request) {
        String token = request.getHeader(HEADER_STRING);
        String username = null;
        if (token != null) {
            // parse the token.
            Map<String,Object> body = Jwts.parser()
                    .setSigningKey(SECRET)
                    .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                    .getBody();
            username = (String) (body.get("username"));
            if(username == null)
                throw new TokenValidationException("Wrong token without username");
        }else{
            throw new TokenValidationException("Missing token");
        }
        return username;
    }

    static class TokenValidationException extends RuntimeException {
        public TokenValidationException(String msg) {
            super(msg);
        }
    }
}