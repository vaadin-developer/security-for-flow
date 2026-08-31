package eu.jsentinel.jcustos.dx.internal;

import eu.jsentinel.jcustos.dx.bootstrap.OidcBootstrap;
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
import java.util.Objects;

/**
 * Records the fluent {@code .oidc(...)} calls into an {@link OidcState} (V00.78).
 * Pure recorder — validation runs in
 * {@code AbstractJCustosBootstrap.applyOidcConfiguration(...)}.
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

  @Override
  public OidcBootstrap vendor(eu.jsentinel.jcustos.oidc.api.VendorProfile profile) {
    java.util.Objects.requireNonNull(profile, "profile");
    profile.rolesMapper().ifPresent(state::rolesMapper);
    profile.permissionsMapper().ifPresent(state::permissionsMapper);
    profile.tenantMapper().ifPresent(state::tenantMapper);
    profile.subjectMapper().ifPresent(state::claimsMapper);
    return this;
  }
}
