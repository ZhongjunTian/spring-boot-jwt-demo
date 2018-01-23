package security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;



/*
    https://auth0.com/blog/securing-spring-boot-with-jwts/
	https://github.com/auth0-blog/spring-boot-jwts
	https://github.com/szerhusenBC/jwt-spring-security-demo
*/

@SpringBootApplication
@RestController
public class Application {

    @GetMapping("/api/admin")
    @PreAuthorize("hasAuthority('ADMIN_USER')")
    public @ResponseBody
    Object helloToAdmin(String userId) {
        return "Hello World! You are ADMIN ";
    }

    @GetMapping("/api/hello")
    public @ResponseBody
    Object hello(String userId) {
        return "Hello World! You have valid token";
    }

    @PostMapping("/login")
    public void login(HttpServletResponse response,
                      @RequestBody AccountCredentials credentials) throws IOException {
        if (isValidPassword(credentials)) {
            String role = credentials.username.equals("admin") ? "ADMIN_USER" : "REGULAR_USER";
            response.addHeader(JwtUtil.HEADER_STRING, JwtUtil.generateToken(role));
        } else {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Wrong credentials");
        }
    }


    private boolean isValidPassword(AccountCredentials cr) {
        //we just have 2 hardcoded user
        if ("admin".equals(cr.username) && "admin".equals(cr.password)
                || "user".equals(cr.username) && "user".equals(cr.password)) {
            return true;
        }
        return false;
    }


    public static class AccountCredentials {
        public String username;
        public String password;
    }

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}