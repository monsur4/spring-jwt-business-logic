package com.mon.springjwt.springjwtbusinesslogic.provider;

import com.mon.springjwt.springjwtbusinesslogic.authentication.OtpAuthentication;
import com.mon.springjwt.springjwtbusinesslogic.model.User;
import com.mon.springjwt.springjwtbusinesslogic.proxy.AuthenticationServerProxy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class OtpAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    AuthenticationServerProxy proxy;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String code = authentication.getCredentials().toString();

        var result = proxy.sendOTP(username, code);
        if(result){
            return new OtpAuthentication(username, code);
        }else{
            throw new BadCredentialsException("Bad Credentials.");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OtpAuthentication.class.isAssignableFrom(authentication);
    }
}
