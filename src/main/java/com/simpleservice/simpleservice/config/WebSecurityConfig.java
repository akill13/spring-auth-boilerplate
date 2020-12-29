package com.simpleservice.simpleservice.config;

import com.simpleservice.simpleservice.security.JwtAccessDeniedHandler;
import com.simpleservice.simpleservice.security.JwtAuthenticationEntryPoint;
import com.simpleservice.simpleservice.security.jwt.JWTConfigurer;
import com.simpleservice.simpleservice.security.jwt.TokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private final CorsFilter corsFilter;
    @Autowired
    private JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Autowired
    private JwtAuthenticationEntryPoint authenticationErrorHandler;

    @Autowired
    private TokenProvider tokenProvider;

    public WebSecurityConfig(TokenProvider tokenProvider, CorsFilter corsFilter, JwtAccessDeniedHandler jwtAccessDeniedHandler, JwtAuthenticationEntryPoint authenticationErrorHandler) {
        this.tokenProvider=tokenProvider;
        this.corsFilter=corsFilter;
        this.jwtAccessDeniedHandler=jwtAccessDeniedHandler;
        this.authenticationErrorHandler=authenticationErrorHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity webSecurity) {
        webSecurity.ignoring()
                .antMatchers(HttpMethod.OPTIONS, "/**")
                .antMatchers(
                        "/",
                        "/*.html",
                        "/favicon.ico",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js",
                        "/h2-console/**"
                );
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // we don't need CSRF because our token is invulnerable
                .csrf().disable()

                .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)

                .exceptionHandling()
                .authenticationEntryPoint(authenticationErrorHandler)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // enable h2-console
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                // create no session
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeRequests()
                .antMatchers("/api/auth").permitAll()
                // .antMatchers("/api/register").permitAll()
                // .antMatchers("/api/activate").permitAll()
                // .antMatchers("/api/account/reset-password/init").permitAll()
                // .antMatchers("/api/account/reset-password/finish").permitAll()

                .antMatchers("/api/person").hasAuthority("ROLE_USER")
                .antMatchers("/api/test").hasAuthority("ROLE_ADMIN")

                .anyRequest().authenticated()

                .and()
                .apply(securityConfigurerAdapter());
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("test").password(passwordEncoder().encode("test")).roles("USER");
    }


    private JWTConfigurer securityConfigurerAdapter() {
        return new JWTConfigurer(tokenProvider);
    }

}
