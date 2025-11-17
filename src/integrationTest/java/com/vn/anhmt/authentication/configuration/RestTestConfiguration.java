package com.vn.anhmt.authentication.configuration;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

@TestConfiguration
public class RestTestConfiguration {

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        var requestFactory = new HttpComponentsClientHttpRequestFactory();

        ClientHttpRequestInterceptor loggingInterceptor = (request, body, execution) -> {
            System.out.println("\n--- REQUEST ---");
            System.out.println(request.getMethod() + " " + request.getURI());
            request.getHeaders().forEach((k, v) -> System.out.println(k + ": " + v));
            if (body.length > 0) {
                System.out.println("Body: " + new String(body));
            }

            var response = execution.execute(request, body);

            System.out.println("\n--- RESPONSE ---");
            System.out.println("Status: " + response.getStatusCode());
            response.getHeaders().forEach((k, v) -> System.out.println(k + ": " + v));

            return response;
        };

        return builder.requestFactory(() -> requestFactory)
                .additionalInterceptors(loggingInterceptor)
                .build();
    }
}
