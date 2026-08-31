package eu.jsentinel.jcustos.dx.internal;

import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oidc.api.ClaimsToPermissionsMapper;
import eu.jsentinel.jcustos.oidc.api.ClaimsToRolesMapper;
import eu.jsentinel.jcustos.oidc.api.ClaimsToSubjectMapper;
import eu.jsentinel.jcustos.oidc.api.ClaimsToTenantMapper;
import eu.jsentinel.jcustos.oidc.api.IdTokenValidator;
import eu.jsentinel.jcustos.oidc.api.OidcDiscoveryClient;
import eu.jsentinel.jcustos.oidc.api.UserInfoClient;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Mutable accumulator for the V00.78 {@code .oidc(...)} sub-builder. Holds the
 * recorded OIDC Relying-Party configuration; consumed + validated by
 * {@code AbstractJSentinelBootstrap.applyOidcConfiguration(...)}. {@code nonce} is
 * required by default (the secure default).
 */
public final class OidcState {

  private String issuer;
  private String clientId;
  private ClientAuthentication clientAuthentication;
  private URI redirectUri;
  private final Set<String> scopes = new LinkedHashSet<>();
  private boolean requireNonce = true;
  private Duration maxAge;
  private final Set<String> acrValues = new LinkedHashSet<>();
  private boolean userInfoEnabled;
  private boolean logoutEnabled;
  private URI postLogoutRedirectUri;
  private ClaimsToSubjectMapper claimsMapper;
  private ClaimsToRolesMapper rolesMapper;
  private ClaimsToPermissionsMapper permissionsMapper;
  private ClaimsToTenantMapper tenantMapper;
  private OidcDiscoveryClient discoveryClient;
  private IdTokenValidator idTokenValidator;
  private UserInfoClient userInfoClient;

  public String issuer() {
    return issuer;
  }

  public void issuer(String value) {
    this.issuer = value;
  }

  public String clientId() {
    return clientId;
  }

  public void clientId(String value) {
    this.clientId = value;
  }

  public ClientAuthentication clientAuthentication() {
    return clientAuthentication;
  }

  public void clientAuthentication(ClientAuthentication value) {
    this.clientAuthentication = value;
  }

  public URI redirectUri() {
    return redirectUri;
  }

  public void redirectUri(URI value) {
    this.redirectUri = value;
  }

  public Set<String> scopes() {
    return Set.copyOf(scopes);
  }

  public void addScopes(String... values) {
    if (values != null) {
      for (String v : values) {
        if (v != null && !v.isBlank()) {
          scopes.add(v);
        }
      }
    }
  }

  public boolean requireNonce() {
    return requireNonce;
  }

  public void requireNonce(boolean value) {
    this.requireNonce = value;
  }

  public Duration maxAge() {
    return maxAge;
  }

  public void maxAge(Duration value) {
    this.maxAge = value;
  }

  public Set<String> acrValues() {
    return Set.copyOf(acrValues);
  }

  public void addAcrValues(String... values) {
    if (values != null) {
      for (String v : values) {
        if (v != null && !v.isBlank()) {
          acrValues.add(v);
        }
      }
    }
  }

  public boolean userInfoEnabled() {
    return userInfoEnabled;
  }

  public void userInfoEnabled(boolean value) {
    this.userInfoEnabled = value;
  }

  public boolean logoutEnabled() {
    return logoutEnabled;
  }

  public void logoutEnabled(boolean value) {
    this.logoutEnabled = value;
  }

  public URI postLogoutRedirectUri() {
    return postLogoutRedirectUri;
  }

  public void postLogoutRedirectUri(URI value) {
    this.postLogoutRedirectUri = value;
  }

  public ClaimsToSubjectMapper claimsMapper() {
    return claimsMapper;
  }

  public void claimsMapper(ClaimsToSubjectMapper value) {
    this.claimsMapper = value;
  }

  public ClaimsToRolesMapper rolesMapper() {
    return rolesMapper;
  }

  public void rolesMapper(ClaimsToRolesMapper value) {
    this.rolesMapper = value;
  }

  public ClaimsToPermissionsMapper permissionsMapper() {
    return permissionsMapper;
  }

  public void permissionsMapper(ClaimsToPermissionsMapper value) {
    this.permissionsMapper = value;
  }

  public ClaimsToTenantMapper tenantMapper() {
    return tenantMapper;
  }

  public void tenantMapper(ClaimsToTenantMapper value) {
    this.tenantMapper = value;
  }

  public OidcDiscoveryClient discoveryClient() {
    return discoveryClient;
  }

  public void discoveryClient(OidcDiscoveryClient value) {
    this.discoveryClient = value;
  }

  public IdTokenValidator idTokenValidator() {
    return idTokenValidator;
  }

  public void idTokenValidator(IdTokenValidator value) {
    this.idTokenValidator = value;
  }

  public UserInfoClient userInfoClient() {
    return userInfoClient;
  }

  public void userInfoClient(UserInfoClient value) {
    this.userInfoClient = value;
  }

  /** @return true once any OIDC field was recorded (an empty {@code .oidc(o->{})} is silent). */
  public boolean hasAnySelection() {
    return issuer != null || clientId != null || redirectUri != null
        || !scopes.isEmpty() || logoutEnabled || userInfoEnabled;
  }
}
