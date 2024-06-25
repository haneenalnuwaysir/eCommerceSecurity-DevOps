package com.example.demo.Security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

/**
 * JWT Authentication Verification Filter, a filter used to override spring security filter.
 * <p>BasicAuthenticationFilter: Processes a HTTP request's BASIC authorization headers, putting the result into the SecurityContextHolder.</p>
 * <p>SecurityContextHolder: The security context is the user account that the system uses to enforce security when a thread attempts to access a securable object.</p>
 * @see <a href="https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/authentication/www/BasicAuthenticationFilter.html">BasicAuthenticationFilter</a>
 */
@Component
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    /**
     * <p>Creates an instance which will authenticate against the supplied AuthenticationManager and which will ignore failed authentication attempts, allowing the request to proceed down the filter chain.</p>
     * @param authManager the bean to submit authentication requests to
     */
    public JWTAuthorizationFilter(AuthenticationManager authManager) {
        super(authManager);
    }

    /**
     * HTTP request header been checked:
     * <p>If we don't have bear prefix token in our header, then authentication process not done</p>
     * @param req HttpServletRequest
     * @param res HttpServletResponse
     * @param chain FilterChain
     * @throws IOException
     * @throws ServletException
     * @see <a href="https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html">HttpServletRequest</a>
     * @see <a href="https://docs.oracle.com/javaee/7/api/javax/servlet/FilterChain.html">FilterChain</a>
     */
    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        String header = req.getHeader(SecurityConstants.HEADER_STRING);
        // If the header not with the prefix that been required,
        // Causes the next filter in the chain to be invoked, or if the calling filter is the last filter in the chain, causes the resource at the end of the chain to be invoked.
        // This is the last filter, because return.
        if (header == null || !header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        // If the header contains the bear token, get the authentication
        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    /**
     * get authentication (token) from request
     * @param req
     * @return
     */
    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest req) {
        String token = req.getHeader(SecurityConstants.HEADER_STRING);
        if (token != null) {
            String user = JWT.require(HMAC512(SecurityConstants.SECRET.getBytes())).build()
                    .verify(token.replace(SecurityConstants.TOKEN_PREFIX, ""))
                    .getSubject();
            if (user != null) {
                return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
            }
            return null;
        }
        return null;
    }

}