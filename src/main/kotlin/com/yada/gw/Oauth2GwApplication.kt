package com.yada.gw

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class Oauth2GwApplication

fun main(args: Array<String>) {
	runApplication<Oauth2GwApplication>(*args)
}

