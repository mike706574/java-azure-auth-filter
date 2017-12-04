package fun.mike.azure.auth;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.ext.Provider;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

@Provider
@PreMatching
public class AzureAuthFilter implements ContainerRequestFilter {
    private final String clientId;
    private final String tenantId;

    private final TypeReference STRING_MAP = new TypeReference<Map<String, Object>>() {};

    public AzureAuthFilter(String clientId, String tenantId) {
        this.clientId = clientId;
        this.tenantId = tenantId;
    }

    public void filter(ContainerRequestContext ctx) throws IOException {
        String header = ctx.getHeaderString(HttpHeaders.AUTHORIZATION);
        String token = getBearerTokenFromAuthorizationHeader(header);
        String jwksUrl = getJwksUrl();

        TokenValidationResult result = validateToken(token, jwksUrl);

        if (result.failed()) {
            throw new InternalServerErrorException(result.getMessage());
        }

        if (!result.valid()) {
            unauthorized(result.getMessage());
        }
    }

    private String getBearerTokenFromAuthorizationHeader(String header) {
        if (header == null) {
            unauthorized("No \"Authorization\" header present.");
        }

        List<String> parts = Arrays.asList(header.split(" "));

        if (parts.size() != 2) {
            unauthorized("Malformed \"Authorization\" header.");
        }

        String scheme = parts.get(0);

        if (!"Bearer".equals(scheme)) {
            String message = String.format("Unexpected authentication scheme %s in the \"Authorization\" header; expected \"Bearer\".",
                    scheme);
            unauthorized(message);
        }

        return parts.get(1);
    }

    private String getJwksUrl() {
        URL metadataURL = null;

        String metadataPath = String.format("https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration",
                tenantId);
        try {
            metadataURL = new URL(metadataPath);
        } catch (MalformedURLException ex) {
            String message = String.format("OpenID provider metadata URL \"%s\" is malformed.",
                    metadataPath);
            throw new InternalServerErrorException(message);
        }

        Map<String, Object> metadata = null;
        try {
            metadata = new ObjectMapper().readValue(metadataURL, STRING_MAP);
        } catch (IOException ex) {
            String message = String.format("Failed to parse OpenID provider metadata from \"%s\".",
                    metadataURL);
            throw new InternalServerErrorException(message);
        }

        if (metadata.containsKey("jwks_uri")) {
            return (String) metadata.get("jwks_uri");
        }

        String message = String.format("No jwks_uri property present in OpenID provider metadata retrieved from \"%s\".",
                metadataPath);
        throw new InternalServerErrorException();
    }

    private TokenValidationResult validateToken(String token, String jwksUrl) {
        JWKSource<SecurityContext> jwksSource = null;
        try {
            jwksSource = new RemoteJWKSet(new URL(jwksUrl));
        } catch (MalformedURLException ex) {
            String message = String.format("JWKS URL \"%s\" retrieved from OpenID provider is malformed.",
                    jwksUrl);
            return TokenValidationResult.failed(message);
        }

        return validateToken(token, jwksSource);
    }

    private TokenValidationResult validateToken(String token, JWKSource<SecurityContext> jwksSource) {
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();

        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        JWSKeySelector keySelector = new JWSVerificationKeySelector(expectedJWSAlg, jwksSource);
        jwtProcessor.setJWSKeySelector(keySelector);

        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier() {
            @Override
            public void verify(JWTClaimsSet claimsSet)
                    throws BadJWTException {

                super.verify(claimsSet);

                if (claimsSet.getExpirationTime() == null) {
                    throw new BadJWTException("Missing required token expiration claim.");
                }

                String subject = claimsSet.getSubject();
                if (clientId.equals(claimsSet.getSubject())) {
                    String message = String.format("Expected subject \"%s\" to be \"%s\".",
                            clientId,
                            subject);
                    throw new BadJWTException(message);
                }

                String expectedIssuer = String.format("https://sts.windows.net/%s/",
                        tenantId);

                if (!expectedIssuer.equals(claimsSet.getIssuer())) {
                    String message = String.format("Expected issuer \"%s\" to be \"%s\".",
                            clientId,
                            expectedIssuer);
                    throw new BadJWTException(message);
                }
            }
        });

        try {
            JWTClaimsSet claimsSet = jwtProcessor.process(token, null);
            return TokenValidationResult.valid(claimsSet.getClaims());
        } catch (ParseException | JOSEException | BadJOSEException ex) {
            return TokenValidationResult.invalid(ex.getMessage());
        }
    }

    private void unauthorized(String message) {
        throw new NotAuthorizedException(message);
    }
}
