package com.example.demo.Security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter{
    Logger log = LoggerFactory.getLogger(JWTAuthenticationFilter.class);
    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    //get token and 解析他
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //取得在header的token: Authorization : Bearer token
        String header = request.getHeader(SecurityConstants.HEADER_STRING);
        //如果發現沒有token
        if(header==null||!header.startsWith(SecurityConstants.TOKEN_PREFIX)){
            log.warn("[Exception] -> Access is denied.");
            //return nothing;
            chain.doFilter(request,response);
            return;
        }

        //reads the JWT from the authorization header, validate the token
        UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        try {
            chain.doFilter(request, response);
        } catch (IOException | ServletException e) {
            log.error("[Exception] -> Validate the token");
        }
    }


    //this method reads the JWT from the Authorization header, and then uses JWT to validate the token.
    //If everything is in place, we set the user in the SecurityContext and allow the request to move on.
    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request){
        //get token if exist
        String token = request.getHeader(SecurityConstants.HEADER_STRING);
        if (token != null) {
            // parse the token.
            String user = JWT.require(Algorithm.HMAC512(SecurityConstants.SECRET.getBytes()))
                    .build()
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