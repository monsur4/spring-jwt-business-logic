package com.mon.springjwt.springjwtbusinesslogic.config;

import com.mon.springjwt.springjwtbusinesslogic.filter.InitialAuthenticationFilter;
import com.mon.springjwt.springjwtbusinesslogic.filter.JwtAuthenticationFilter;
import com.mon.springjwt.springjwtbusinesslogic.provider.OtpAuthenticationProvider;
import com.mon.springjwt.springjwtbusinesslogic.provider.UsernamePasswordAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private InitialAuthenticationFilter initialAuthenticationFilter;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider;

    @Autowired
    private OtpAuthenticationProvider otpAuthenticationProvider;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(usernamePasswordAuthenticationProvider)
                .authenticationProvider(otpAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.addFilterAt(initialAuthenticationFilter, BasicAuthenticationFilter.class)
                .addFilterAfter(jwtAuthenticationFilter, BasicAuthenticationFilter.class);
        http.authorizeRequests().anyRequest().authenticated(); // basically saying, all requests should pass through the filters
        // i.e the initialAuthentication and jwtAuthenticationFilter. The filters thereby hold the responsibility of how to
        // authenticate the requests. Otherwise, some or all the endpoints would not pass through the filter, so our jwt implementation
        // would have been of no use
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
