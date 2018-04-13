package fun.mike.azure.auth;

import java.security.Principal;
import java.util.Collection;
import javax.ws.rs.core.SecurityContext;

class SimpleSecurityContext implements SecurityContext {
    private final SecurityContext securityContext;
    private final SimpleUserPrincipal userPrincipal;
    private final Collection<String> roles;

    public SimpleSecurityContext(SecurityContext securityContext,
            String name,
            Collection<String> roles) {
        this.securityContext = securityContext;
        this.userPrincipal = new SimpleUserPrincipal(name);
        this.roles = roles;
    }

    @Override
    public Principal getUserPrincipal() {
        return userPrincipal;
    }

    @Override
    public boolean isUserInRole(String role) {
        return roles.contains(role);
    }

    @Override
    public boolean isSecure() {
        return securityContext.isSecure();
    }

    @Override
    public String getAuthenticationScheme() {
        return "AZURE";
    }
}
