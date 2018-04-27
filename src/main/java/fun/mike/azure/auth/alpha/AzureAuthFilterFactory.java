package fun.mike.azure.auth.alpha;

public class AzureAuthFilterFactory {
    public static AzureAuthFilter simple(String tenantId, String clientId) {
        Authenticator authenticator = AuthenticatorFactory.build(tenantId, clientId);
        return new AzureAuthFilter(authenticator);
    }

    public static AzureAuthFilter withPathPattern(String tenantId, String clientId, String pathPattern) {
        Authenticator authenticator = AuthenticatorFactory.build(tenantId, clientId);
        return new AzureAuthFilter(authenticator, pathPattern);
    }
}
