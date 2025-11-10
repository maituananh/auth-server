package com.vn.anhmt.authentication.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.vn.anhmt.authentication.configuration.custom.user.UserDetailsCustom;
import com.vn.anhmt.authentication.configuration.custom.user.UserDetailsCustomMixin;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;

@Configuration
public class ObjectMapperConfiguration {

    @Bean
    public com.fasterxml.jackson.databind.Module immutableCollectionsModule() {
        SimpleModule module = new SimpleModule();
        module.addAbstractTypeMapping(List.class, ArrayList.class);
        module.addAbstractTypeMapping(Map.class, HashMap.class);
        return module;
    }

    @Bean
    public ObjectMapper objectMapper(Jackson2ObjectMapperBuilder builder) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        mapper.addMixIn(UserDetailsCustom.class, UserDetailsCustomMixin.class);
        return mapper;
    }
}
