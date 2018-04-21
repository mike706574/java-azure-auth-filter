# azure-auth-filter-alpha

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/fun.mike/azure-auth-filter-alpha/badge.svg)](https://maven-badges.herokuapp.com/maven-central/fun.mike/azure-auth-filter-alpha)
[![Javadocs](https://www.javadoc.io/badge/fun.mike/azure-auth-filter-alpha.svg)](https://www.javadoc.io/doc/fun.mike/azure-auth-filter-alpha)

Jersey Azure auth filter.

## Usage

With Dropwizard:

```java
final String tenantId = "c834c34e-bbd3-4ea1-c2c2-51daeff91aa32";
final String clientId = "ae33c32e-d2f2-4992-a4b2-51d03e7c8677";

AzureAuthFilter azureAuthFilter =
    new AzureAuthFilter(tenantId,
                        clientId,
                        "/api.*");

environment.jersey().register(new AuthDynamicFeature(azureAuthFilter));
```

Tweak appropriately for your web framework of choice.

## Build

[![CircleCI](https://circleci.com/gh/mike706574/java-azure-auth-filter.svg?style=svg)](https://circleci.com/gh/mike706574/java-azure-auth-filter)

## Copyright and License

This project is licensed under the terms of the Apache 2.0 license.
