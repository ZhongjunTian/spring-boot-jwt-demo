package basic;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtUtil {
    public static final long EXPIRATION_TIME = 3600_000_000L; // 1000 hour
    static final String SECRET = "ThisIsASecret";
    static final String TOKEN_PREFIX = "Bearer";
    static final String HEADER_STRING = "Authorization";

    public static String generateToken(String username) {
        HashMap<String, Object> map = new HashMap<>();
        //you can put any data in the map
        map.put("username", username);
        String jwt = Jwts.builder()
                .setClaims(map)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();
        return jwt;
    }

    public static void validateToken(String token) {
        try {
            // parse the token.
            Map<String, Object> body = Jwts.parser()
                    .setSigningKey(SECRET)
                    .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                    .getBody();
        }catch (Exception e){
            throw new IllegalStateException("Invalid Token. "+e.getMessage());
        }
    }

    static class TokenValidationException extends RuntimeException {
        public TokenValidationException(String msg) {
            super(msg);
        }
    }
}