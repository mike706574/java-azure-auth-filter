# azure-auth-filter-alpha

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/fun.mike/azure-auth-filter-alpha/badge.svg)](https://maven-badges.herokuapp.com/maven-central/fun.mike/azure-auth-filter-alpha)
[![Javadocs](https://www.javadoc.io/badge/fun.mike/azure-auth-filter-alpha.svg)](https://www.javadoc.io/doc/fun.mike/azure-auth-filter-alpha)

JAX-RS Azure OpenID Connect auth filter.

## Usage

With Dropwizard:

```java
import fun.mike.azure.auth.alpha.AzureAuthFilter;
import io.dropwizard.auth.AuthDynamicFeature;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;

final String tenantId = "c834c34e-bbd3-4ea1-c2c2-51daeff91aa32";
final String clientId = "ae33c32e-d2f2-4992-a4b2-51d03e7c8677";

AzureAuthFilter azureAuthFilter = AzureAuthFilterFactory.simple(tenantId, clientId);

environment.jersey().register(new AuthDynamicFeature(azureAuthFilter));
environment.jersey().register(RolesAllowedDynamicFeature.class);
```

Tweak appropriately for your web framework of choice.

## Build

[![CircleCI](https://circleci.com/gh/mike706574/java-azure-auth-filter.svg?style=svg)](https://circleci.com/gh/mike706574/java-azure-auth-filter)

## Copyright and License

This project is licensed under the terms of the Apache 2.0 license.
