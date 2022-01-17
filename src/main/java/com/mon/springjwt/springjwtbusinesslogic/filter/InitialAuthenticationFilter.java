package com.mon.springjwt.springjwtbusinesslogic.filter;

import com.mon.springjwt.springjwtbusinesslogic.authentication.OtpAuthentication;
import com.mon.springjwt.springjwtbusinesslogic.authentication.UsernamePasswordAuthentication;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
public class InitialAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    AuthenticationManager authenticationManager;

    @Value("${jwt.signing.key}")
    private String signingKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String username  = request.getHeader("username");
        String password = request.getHeader("password");
        String code = request.getHeader("code");

        if(code == null){
            var auth = new UsernamePasswordAuthentication(username, password);
            authenticationManager.authenticate(auth);
        }else{
            var auth = new OtpAuthentication(username, code);
            authenticationManager.authenticate(auth);

            // if no exception is thrown from above line, it means the otp code was correct
            // the lines below which build and adds the jwt to the response will be run
            SecretKey key = Keys.hmacShaKeyFor(signingKey.getBytes(StandardCharsets.UTF_8));

            String jwt = Jwts.builder()
                    .setClaims(Map.of("username", username))
                    .signWith(key)
                    .compact();

            response.setHeader("Authorization", jwt); // only sets the header to jwt,
            // it doesn't do any form of adding the user to the security context
        }


    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        // when request path is /login, this filter should not be applied
        // however the unary NOT operator reverse this to
        // the filter should be applied if and only if the request path is /login
        return !request.getServletPath().equals("/login");
    }
}
