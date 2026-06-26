package com.svenruppert.jsentinel.dx.internal;

import com.svenruppert.jsentinel.dx.bootstrap.OidcBootstrap;
import com.svenruppert.jsentinel.oauth2.api.ClientAuthentication;
import com.svenruppert.jsentinel.oidc.api.ClaimsToPermissionsMapper;
import com.svenruppert.jsentinel.oidc.api.ClaimsToRolesMapper;
import com.svenruppert.jsentinel.oidc.api.ClaimsToSubjectMapper;
import com.svenruppert.jsentinel.oidc.api.ClaimsToTenantMapper;
import com.svenruppert.jsentinel.oidc.api.IdTokenValidator;
import com.svenruppert.jsentinel.oidc.api.OidcDiscoveryClient;
import com.svenruppert.jsentinel.oidc.api.UserInfoClient;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/**
 * Records the fluent {@code .oidc(...)} calls into an {@link OidcState} (V00.78).
 * Pure recorder — validation runs in
 * {@code AbstractJSentinelBootstrap.applyOidcConfiguration(...)}.
 */
public final class RecordingOidcBootstrap implements OidcBootstrap {

  private final OidcState state;

  public RecordingOidcBootstrap(OidcState state) {
    this.state = Objects.requireNonNull(state, "state");
  }

  @Override
  public OidcBootstrap issuer(String issuer) {
    state.issuer(issuer);
    return this;
  }

  @Override
  public OidcBootstrap clientId(String clientId) {
    state.clientId(clientId);
    return this;
  }

  @Override
  public OidcBootstrap clientAuthentication(ClientAuthentication auth) {
    state.clientAuthentication(auth);
    return this;
  }

  @Override
  public OidcBootstrap redirectUri(URI uri) {
    state.redirectUri(uri);
    return this;
  }

  @Override
  public OidcBootstrap scope(String... scopes) {
    state.addScopes(scopes);
    return this;
  }

  @Override
  public OidcBootstrap requireNonce(boolean require) {
    state.requireNonce(require);
    return this;
  }

  @Override
  public OidcBootstrap maxAge(Duration maxAge) {
    state.maxAge(maxAge);
    return this;
  }

  @Override
  public OidcBootstrap acrValues(String... acrValues) {
    state.addAcrValues(acrValues);
    return this;
  }

  @Override
  public OidcBootstrap userInfoEnabled(boolean enabled) {
    state.userInfoEnabled(enabled);
    return this;
  }

  @Override
  public OidcBootstrap logoutEnabled(boolean enabled) {
    state.logoutEnabled(enabled);
    return this;
  }

  @Override
  public OidcBootstrap postLogoutRedirectUri(URI uri) {
    state.postLogoutRedirectUri(uri);
    return this;
  }

  @Override
  public OidcBootstrap claimsMapper(ClaimsToSubjectMapper mapper) {
    state.claimsMapper(mapper);
    return this;
  }

  @Override
  public OidcBootstrap rolesMapper(ClaimsToRolesMapper mapper) {
    state.rolesMapper(mapper);
    return this;
  }

  @Override
  public OidcBootstrap permissionsMapper(ClaimsToPermissionsMapper mapper) {
    state.permissionsMapper(mapper);
    return this;
  }

  @Override
  public OidcBootstrap tenantMapper(ClaimsToTenantMapper mapper) {
    state.tenantMapper(mapper);
    return this;
  }

  @Override
  public OidcBootstrap discoveryClient(OidcDiscoveryClient client) {
    state.discoveryClient(client);
    return this;
  }

  @Override
  public OidcBootstrap idTokenValidator(IdTokenValidator validator) {
    state.idTokenValidator(validator);
    return this;
  }

  @Override
  public OidcBootstrap userInfoClient(UserInfoClient client) {
    state.userInfoClient(client);
    return this;
  }
}
