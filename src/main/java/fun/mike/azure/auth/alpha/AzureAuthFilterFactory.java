package fun.mike.azure.auth.alpha;

public class AzureAuthFilterFactory {
    public static AzureAuthFilter simple(String tenantId, String clientId, int jwksConnectTimeout, int jwksReadTimeout) {
        Authenticator authenticator = AuthenticatorFactory.build(tenantId, clientId, jwksConnectTimeout, jwksReadTimeout);
        return new AzureAuthFilter(authenticator);
    }

    public static AzureAuthFilter withPathPattern(String tenantId, String clientId, int jwksConnectTimeout, int jwksReadTimeout, String pathPattern) {
        Authenticator authenticator = AuthenticatorFactory.build(tenantId, clientId, jwksConnectTimeout, jwksReadTimeout);
        return new AzureAuthFilter(authenticator, pathPattern);
    }
}
