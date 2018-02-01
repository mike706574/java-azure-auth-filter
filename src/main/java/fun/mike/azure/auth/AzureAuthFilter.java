package fun.mike.azure.auth;

import java.io.IOException;
import java.util.Map;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.ext.Provider;

@Provider
@PreMatching
public class AzureAuthFilter implements ContainerRequestFilter {
    private final String tenantId;
    private final String clientId;


    public AzureAuthFilter(String tenantId, String clientId) {
        this.tenantId = tenantId;
        this.clientId = clientId;
    }

    public void filter(ContainerRequestContext ctx) throws IOException {
        String header = ctx.getHeaderString(HttpHeaders.AUTHORIZATION);

        AuthenticationResult result = new Authenticator(tenantId, clientId).authenticate(header);

        if (result.failed()) {
            throw new InternalServerErrorException(result.getMessage());
        }

        if (result.invalid()) {
            throw new NotAuthorizedException(result.getMessage());
        }
    }
}
