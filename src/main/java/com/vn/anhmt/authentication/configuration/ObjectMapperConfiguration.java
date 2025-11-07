package com.vn.anhmt.authentication.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vn.anhmt.authentication.configuration.custom.user.UserDetailsCustomMixin;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;

@Configuration
public class ObjectMapperConfiguration {

    @Bean
    public ObjectMapper objectMapper(Jackson2ObjectMapperBuilder builder) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        mapper.addMixIn(
                com.vn.anhmt.authentication.configuration.custom.user.UserDetailsCustom.class,
                UserDetailsCustomMixin.class);
        return mapper;
    }
}
