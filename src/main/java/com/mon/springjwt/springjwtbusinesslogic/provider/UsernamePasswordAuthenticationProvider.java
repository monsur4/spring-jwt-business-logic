package com.mon.springjwt.springjwtbusinesslogic.provider;

import com.mon.springjwt.springjwtbusinesslogic.authentication.UsernamePasswordAuthentication;
import com.mon.springjwt.springjwtbusinesslogic.proxy.AuthenticationServerProxy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    AuthenticationServerProxy proxy;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        proxy.sendAuth(username, password);
        return new UsernamePasswordAuthentication(username, password); // calls super class method, so should be same
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthentication.class.isAssignableFrom(authentication);
    }
}
