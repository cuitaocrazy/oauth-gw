package com.yada.gw

import org.springframework.beans.factory.ObjectProvider
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.switchIfEmpty

@Component
class OAuthGatewayFilterFactory(private val clientManagerProvider: ObjectProvider<ReactiveOAuth2AuthorizedClientManager>) :
    AbstractGatewayFilterFactory<OAuthGatewayFilterFactory.Config>(Config::class.java) {
    class Config

    override fun apply(config: Config?) = GatewayFilter { exchange, chain ->
        exchange.getPrincipal<OAuth2AuthenticationToken>()
            .flatMap { authentication -> authorizedClient(exchange, authentication) }
            .switchIfEmpty {
                Mono.error(org.springframework.security.access.AccessDeniedException("Access Denied!"))
            }.flatMap {
                chain.filter(exchange)
            }
    }

    private fun authorizedClient(
        exchange: ServerWebExchange,
        oauth2Authentication: OAuth2AuthenticationToken
    ): Mono<OAuth2AuthorizedClient> {
        val clientRegistrationId = oauth2Authentication.authorizedClientRegistrationId
        val request = OAuth2AuthorizeRequest.withClientRegistrationId(clientRegistrationId)
            .principal(oauth2Authentication).build()
        val clientManager = clientManagerProvider.ifAvailable
            ?: return Mono.error(
                IllegalStateException(
                    "No ReactiveOAuth2AuthorizedClientManager bean was found. Did you include the "
                            + "org.springframework.boot:spring-boot-starter-oauth2-client dependency?"
                )
            )
        return clientManager.authorize(request)
    }
}