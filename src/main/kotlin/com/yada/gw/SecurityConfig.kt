package com.yada.gw

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain

@Configuration
class SecurityConfig {
    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        // 认证和授权不由这里发起，将交给下游gateway的filter
        http.authorizeExchange().anyExchange().permitAll()
        http.oauth2Login()
        http.oauth2Client()
        return http.build()
    }
}