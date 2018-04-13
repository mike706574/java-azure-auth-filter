package fun.mike.azure.auth;

import java.security.Principal;

class SimpleUserPrincipal implements Principal {
    private final String name;

    public SimpleUserPrincipal(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }
}
