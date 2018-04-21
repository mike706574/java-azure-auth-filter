package fun.mike.azure.auth;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import javax.annotation.Priority;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Provider
@PreMatching
@Priority(Priorities.AUTHENTICATION)
public class AzureAuthFilter implements ContainerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(AzureAuthFilter.class);

    private final String tenantId;
    private final String clientId;
    private final Pattern pattern;

    public AzureAuthFilter(String tenantId, String clientId, String pattern) {
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.pattern = Pattern.compile(pattern);
    }

    public void filter(ContainerRequestContext ctx) {
        String method = ctx.getMethod();
        String path = ctx.getUriInfo().getRequestUri().getPath();
        String label = String.format("\"%s %s\"", method, path);

        if (method.equals("OPTIONS")) {
            log.trace(label + " Skipping authentication for OPTIONS request.");
        } else if (!pattern.matcher(path).matches()) {
            log.trace(label + " Skipping authentication for unmatched path.");
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

            Map<String, Object> claims = result.getClaims();

            String name = null;

            if(claims.containsKey("name")) {
                name = (String)claims.get("name");
            }

            log.trace(label + "Name: " + name);

            Collection<String> roles;

            if(claims.containsKey("roles")) {
                @SuppressWarnings("unchecked")
                Collection<String> castedRoles = (Collection<String>)claims.get("roles");
                roles = castedRoles;
            } else {
                roles = new HashSet<>();
            }

            log.trace(label + "Roles: " + roles);

            SecurityContext securityContext =
                new SimpleSecurityContext(ctx.getSecurityContext(),
                                          name,
                                          roles);
            ctx.setSecurityContext(securityContext);
        }
    }
}
