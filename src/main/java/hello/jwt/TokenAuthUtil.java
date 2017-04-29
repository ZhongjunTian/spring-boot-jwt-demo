package hello.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class TokenAuthUtil {
    static final long EXPIRATION_TIME = 864_000_000; // 10 days
    static final String SECRET = "ThisIsASecret";
    static final String TOKEN_PREFIX = "Bearer";
    static final String HEADER_STRING = "Authorization";
    static final String USER_NAME = "sub";

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
            try {
                Map<String,Object> body = Jwts.parser()
                        .setSigningKey(SECRET)
                        .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                        .getBody();
                username = (String) (body.get("username"));
            } catch (Exception e) {
                throw new TokenValidationException(e.getMessage());
            }
        }
        return username;
    }

    static class TokenValidationException extends AuthenticationException {
        public TokenValidationException(String msg) {
            super(msg);
        }
    }
}