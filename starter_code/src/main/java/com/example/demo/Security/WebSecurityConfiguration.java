package com.example.demo.Security;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
    private UserDetailsServiceImpl userDetailsService;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    public WebSecurityConfiguration(UserDetailsServiceImpl userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    //a method where we can define which resources are public and which are secured
    //設定那些endpoint可以存取，那些需要authorization,由JWTAuthenticationilter跟JWTAuthorizationFilter來管理
    @Override
    protected void configure(HttpSecurity http){
        // We also configure CORS (Cross-Origin Resource Sharing) support through http.cors() and we add a custom security filter in the Spring Security filter chain.
        try {
            http.cors().and().csrf().disable().authorizeRequests()
                    //we set the SIGN_UP_URL endpoint as being public and everything else as being secured.
                    .antMatchers(HttpMethod.POST, SecurityConstants.SIGN_UP_URL, "/api/cart/addToCart").permitAll()
                    .anyRequest().authenticated()
                    .and()
                    .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                    .addFilter(new JWTAuthorizationFilter(authenticationManager()))
                    // this disables session creation on Spring Security
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        } catch (Exception e) {
            throw new AccessDeniedException(e.getMessage());
        }

    }
    /*
    a method where we defined a custom implementation of UserDetailsService to load user-specific data in the security framework.
    We have also used this method to set the encrypt method used by our application (BCryptPasswordEncoder).
     */
    @Override
    public void configure(AuthenticationManagerBuilder auth){
        try {
            auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
        } catch (Exception e) {
            throw new AccessDeniedException(e.getMessage());
        }
    }

    // a method where we can allow/restrict our CORS support. In our case we left it wide open by permitting requests from any source (/**).
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
        return source;
    }

}