// package com.vn.anhmt.authentication.configuration.interceptor;
//
// import static com.vn.anhmt.authentication.helper.TokenHelper.TOKEN_PREFIX;
// import static org.springframework.http.HttpHeaders.AUTHORIZATION;
//
// import com.vn.anhmt.authentication.configuration.custom.user.UserDetailsCustom;
// import com.vn.anhmt.authentication.domain.User;
// import com.vn.anhmt.authentication.helper.TokenHelper;
// import com.vn.anhmt.authentication.store.TokenStore;
// import com.vn.anhmt.authentication.store.UserStore;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;
// import java.io.IOException;
// import lombok.RequiredArgsConstructor;
// import org.apache.commons.lang3.StringUtils;
// import org.springframework.security.authentication.BadCredentialsException;
// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;
//
// @Component
// @RequiredArgsConstructor
// public class InterceptorConfiguration extends OncePerRequestFilter {
//
//    private final UserStore userStore;
//    private final TokenStore tokenStore;
//    private final TokenHelper tokenHelper;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//            throws ServletException, IOException {
//
//        String token = request.getHeader(AUTHORIZATION);
//
//        if (StringUtils.isEmpty(token)) {
//            doFilter(request, response, filterChain);
//            return;
//        }
//
//        token = token.replace(TOKEN_PREFIX, "");
//
//        if (!tokenHelper.extractTokenType(token).equals(OAuth2TokenType.ACCESS_TOKEN.getValue())) {
//            throw new BadCredentialsException("Invalid token");
//        }
//
//        validAccessToken(token);
//
//        String username = tokenHelper.extractUsername(token);
//
//        if (StringUtils.isEmpty(username)) {
//            return;
//        }
//
//        User user = userStore.findByUsername(username).orElseThrow();
//        UserDetailsCustom userDetailsCustom = toUserDetailsCustom(user);
//
//        UsernamePasswordAuthenticationToken authenticationToken =
//                new UsernamePasswordAuthenticationToken(userDetailsCustom, null, userDetailsCustom.getAuthorities());
//
//        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
//
//        doFilter(request, response, filterChain);
//    }
//
//    private UserDetailsCustom toUserDetailsCustom(User user) {
//        return UserDetailsCustom.builder()
//                .id(user.getId())
//                .username(user.getUsername())
//                .password(user.getPassword())
//                .build();
//    }
//
//    private void validAccessToken(final String accessToken) {
//        tokenStore.findByAccessToken(accessToken).ifPresent(tokenEntity -> {
//            throw new BadCredentialsException("Token was expired %s".formatted(tokenEntity.getAccessToken()));
//        });
//    }
// }
