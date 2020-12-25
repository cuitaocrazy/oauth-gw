package com.yada.gw

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers

@Configuration
class SecurityConfig {
    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity, handler: OAuthLogoutSuccessHandler): SecurityWebFilterChain {
        // 认证和授权不由这里发起，将交给下游gateway的filter
        http.authorizeExchange().anyExchange().permitAll()
        http.logout().requiresLogout(ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, "/logout-oidc"))
            .logoutSuccessHandler(handler)
        http.oauth2Login()
        http.oauth2Client()
        return http.build()
    }
}