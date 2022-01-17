package com.mon.springjwt.springjwtbusinesslogic.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Configuration
public class ProjectConfig {

    @Bean
    public RestTemplate restTemplate(){
        return new RestTemplate();
    }
}
