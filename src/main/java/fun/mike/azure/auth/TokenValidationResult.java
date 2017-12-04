package fun.mike.azure.auth;

import java.util.Map;

public class TokenValidationResult {
    private final boolean failed;
    private final boolean valid;

    private final String message;
    private final Map<String, Object> claims;

    public TokenValidationResult(boolean failed,
                                 boolean valid,
                                 String message,
                                 Map<String, Object> claims) {
        this.failed = failed;
        this.valid = valid;
        this.message = message;
        this.claims = claims;
    }

    public static TokenValidationResult valid(Map<String, Object> claims) {
        return new TokenValidationResult(false, true, null, claims);
    }

    public static TokenValidationResult invalid(String message) {
        return new TokenValidationResult(false, false, message, null);
    }

    public static TokenValidationResult failed(String message) {
        return new TokenValidationResult(true, false, message, null);
    }

    public boolean failed() {
        return failed;
    }

    public boolean valid() {
        return valid;
    }

    public String getMessage() {
        return message;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }
}
