package com.vn.anhmt.authentication.configuration.interceptor;

import static com.vn.anhmt.authentication.helper.TokenHelper.TOKEN_PREFIX;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import com.vn.anhmt.authentication.configuration.custom.user.UserDetailsCustom;
import com.vn.anhmt.authentication.domain.User;
import com.vn.anhmt.authentication.helper.TokenHelper;
import com.vn.anhmt.authentication.store.OAuth2AuthorizationStore;
import com.vn.anhmt.authentication.store.UserStore;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class InterceptorConfiguration extends OncePerRequestFilter {

    private final UserStore userStore;
    private final OAuth2AuthorizationStore oAuth2AuthorizationStore;
    private final TokenHelper tokenHelper;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String token = request.getHeader(AUTHORIZATION);
        String tokenWithoutBearer = StringUtils.removeStart(token, TOKEN_PREFIX);

        if (StringUtils.isEmpty(token)) {
            doFilter(request, response, filterChain);
            return;
        }

        validAccessToken(tokenWithoutBearer);

        String username = tokenHelper.extractUsername(tokenWithoutBearer);

        if (StringUtils.isEmpty(username)) {
            throw new BadCredentialsException("Invalid token");
        }

        User user = getUserByUsername(username);
        UserDetailsCustom userDetailsCustom = UserDetailsCustom.toUserDetailsCustom(user);

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(userDetailsCustom, null, userDetailsCustom.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        doFilter(request, response, filterChain);
    }

    private void validAccessToken(final String accessToken) {
        final var oauth2 = oAuth2AuthorizationStore.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN);

        if (oauth2 == null) {
            throw new BadCredentialsException("Token was expired %s".formatted(accessToken));
        }
    }

    private User getUserByUsername(final String username) {
        return userStore.findByUsername(username).orElseThrow();
    }
}
