package fun.mike.azure.auth;

import java.io.IOException;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.ext.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Provider
@PreMatching
public class AzureAuthFilter implements ContainerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(AzureAuthFilter.class);

    private final String tenantId;
    private final String clientId;

    public AzureAuthFilter(String tenantId, String clientId) {
        this.tenantId = tenantId;
        this.clientId = clientId;
    }

    public void filter(ContainerRequestContext ctx) throws IOException {
        String method = ctx.getMethod();
        String path = ctx.getUriInfo().getRequestUri().getPath();
        String label = String.format("\"%s %s\"", method, path);

        if (method.equals("OPTIONS")) {
            log.trace(label + " Skipping request authentication.");
        } else {
            log.trace(label + " Authenticating request.");

            String header = ctx.getHeaderString(HttpHeaders.AUTHORIZATION);

            AuthenticationResult result = new Authenticator(tenantId,
                                                            clientId)
                    .authenticate(header);

            if (result.failed()) {
                log.error(String.format("%s Request authentication error: %s",
                                        label,
                                        result.getMessage()));
                throw new InternalServerErrorException(result.getMessage());
            }

            if (result.invalid()) {
                log.trace(String.format("%s Unauthenticated request: %s",
                                        label,
                                        result.getMessage()));
                throw new NotAuthorizedException(result.getMessage());
            }

            log.trace(label + " Authenticated request.");
        }
    }
}
