package hello;

import hello.jwt.JwtAuthenticationFilter;
import hello.jwt.TokenAuthUtil;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
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

    @GetMapping("/demo")
    public @ResponseBody Object hellWorld() {
        return "hello world";
    }


    @Bean
    public FilterRegistrationBean jwtFilter() {
        final FilterRegistrationBean registrationBean = new FilterRegistrationBean();
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter();
        filter.setExcludeUrlPatterns("/*.html", "/", "/login");
        registrationBean.setFilter(filter);
        return registrationBean;
    }


    public static final String LOGIN_PATH = "/login";
    @PostMapping(LOGIN_PATH)
    public void login(HttpServletRequest request, HttpServletResponse response,
                                     @RequestBody final AccountCredentials credentials) throws IOException {
        //here we just have one hardcoded username=admin and password=admin
        //TODO add your own user validation code here
        if("admin".equals(credentials.username)
                && "admin".equals(credentials.password))
            TokenAuthUtil.addTokenToHeader(response,credentials.username);
        else
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Wrong credentials");
    }


    public static class AccountCredentials {
        public String username;
        public String password;
    }
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}