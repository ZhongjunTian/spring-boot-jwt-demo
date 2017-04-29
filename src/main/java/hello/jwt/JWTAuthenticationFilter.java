package hello.jwt;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

public class JWTAuthenticationFilter extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {
        try {
            String username = TokenAuthUtil.parseToken((HttpServletRequest) request);
            if (username != null)
                SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList()));
        } catch (TokenAuthUtil.TokenValidationException te) {
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED, te.getMessage());
        } catch (Exception e) {
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED, "invalid token");
        }
        filterChain.doFilter(request, response);
    }
}