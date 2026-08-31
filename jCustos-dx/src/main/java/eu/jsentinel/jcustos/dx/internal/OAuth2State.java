package eu.jsentinel.jcustos.dx.internal;

import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.RefreshTokenFamilyStore;
import eu.jsentinel.jcustos.oauth2.api.StateStore;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Mutable accumulator for the V00.77 {@code .oauth2(...)} sub-builder. Holds the
 * recorded Relying-Party configuration; consumed + validated by
 * {@code AbstractJCustosBootstrap.applyOAuth2Configuration(...)}. PKCE and
 * refresh-rotation default to {@code true} (the secure defaults).
 */
public final class OAuth2State {

  private String clientId;
  private ClientAuthentication clientAuthentication;
  private URI authorizationEndpoint;
  private URI tokenEndpoint;
  private URI revocationEndpoint;
  private URI introspectionEndpoint;
  private URI deviceAuthorizationEndpoint;
  private URI redirectUri;
  private final Set<String> scopes = new LinkedHashSet<>();
  private boolean pkceRequired = true;
  private boolean refreshTokenRotation = true;
  private StateStore stateStore;
  private Duration stateTtl;
  private RefreshTokenFamilyStore refreshTokenFamilyStore;
  private Duration introspectionCacheTtl;

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

  public URI authorizationEndpoint() {
    return authorizationEndpoint;
  }

  public void authorizationEndpoint(URI value) {
    this.authorizationEndpoint = value;
  }

  public URI tokenEndpoint() {
    return tokenEndpoint;
  }

  public void tokenEndpoint(URI value) {
    this.tokenEndpoint = value;
  }

  public URI revocationEndpoint() {
    return revocationEndpoint;
  }

  public void revocationEndpoint(URI value) {
    this.revocationEndpoint = value;
  }

  public URI introspectionEndpoint() {
    return introspectionEndpoint;
  }

  public void introspectionEndpoint(URI value) {
    this.introspectionEndpoint = value;
  }

  public URI deviceAuthorizationEndpoint() {
    return deviceAuthorizationEndpoint;
  }

  public void deviceAuthorizationEndpoint(URI value) {
    this.deviceAuthorizationEndpoint = value;
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

  public boolean pkceRequired() {
    return pkceRequired;
  }

  public void pkceRequired(boolean value) {
    this.pkceRequired = value;
  }

  public boolean refreshTokenRotation() {
    return refreshTokenRotation;
  }

  public void refreshTokenRotation(boolean value) {
    this.refreshTokenRotation = value;
  }

  public StateStore stateStore() {
    return stateStore;
  }

  public void stateStore(StateStore value) {
    this.stateStore = value;
  }

  public Duration stateTtl() {
    return stateTtl;
  }

  public void stateTtl(Duration value) {
    this.stateTtl = value;
  }

  public RefreshTokenFamilyStore refreshTokenFamilyStore() {
    return refreshTokenFamilyStore;
  }

  public void refreshTokenFamilyStore(RefreshTokenFamilyStore value) {
    this.refreshTokenFamilyStore = value;
  }

  public Duration introspectionCacheTtl() {
    return introspectionCacheTtl;
  }

  public void introspectionCacheTtl(Duration value) {
    this.introspectionCacheTtl = value;
  }

  /** @return true once any endpoint / client-id was recorded (an empty {@code .oauth2(o->{})} is silent). */
  public boolean hasAnySelection() {
    return clientId != null || tokenEndpoint != null || authorizationEndpoint != null
        || deviceAuthorizationEndpoint != null || introspectionEndpoint != null
        || revocationEndpoint != null || redirectUri != null;
  }
}
