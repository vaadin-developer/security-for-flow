package com.svenruppert.jsentinel.dx.internal;

import com.svenruppert.jsentinel.dx.bootstrap.OAuth2Bootstrap;
import com.svenruppert.jsentinel.oauth2.api.ClientAuthentication;
import com.svenruppert.jsentinel.oauth2.api.RefreshTokenFamilyStore;
import com.svenruppert.jsentinel.oauth2.api.StateStore;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/**
 * Records the fluent {@code .oauth2(...)} calls into an {@link OAuth2State}
 * (V00.77). Pure recorder — no validation here; the STRICT / INFO checks run in
 * {@code AbstractJSentinelBootstrap.applyOAuth2Configuration(...)}.
 */
public final class RecordingOAuth2Bootstrap implements OAuth2Bootstrap {

  private final OAuth2State state;

  public RecordingOAuth2Bootstrap(OAuth2State state) {
    this.state = Objects.requireNonNull(state, "state");
  }

  @Override
  public OAuth2Bootstrap clientId(String clientId) {
    state.clientId(clientId);
    return this;
  }

  @Override
  public OAuth2Bootstrap clientAuthentication(ClientAuthentication auth) {
    state.clientAuthentication(auth);
    return this;
  }

  @Override
  public OAuth2Bootstrap authorizationEndpoint(URI uri) {
    state.authorizationEndpoint(uri);
    return this;
  }

  @Override
  public OAuth2Bootstrap tokenEndpoint(URI uri) {
    state.tokenEndpoint(uri);
    return this;
  }

  @Override
  public OAuth2Bootstrap revocationEndpoint(URI uri) {
    state.revocationEndpoint(uri);
    return this;
  }

  @Override
  public OAuth2Bootstrap introspectionEndpoint(URI uri) {
    state.introspectionEndpoint(uri);
    return this;
  }

  @Override
  public OAuth2Bootstrap deviceAuthorizationEndpoint(URI uri) {
    state.deviceAuthorizationEndpoint(uri);
    return this;
  }

  @Override
  public OAuth2Bootstrap redirectUri(URI uri) {
    state.redirectUri(uri);
    return this;
  }

  @Override
  public OAuth2Bootstrap scope(String... scopes) {
    state.addScopes(scopes);
    return this;
  }

  @Override
  public OAuth2Bootstrap pkceRequired(boolean required) {
    state.pkceRequired(required);
    return this;
  }

  @Override
  public OAuth2Bootstrap refreshTokenRotation(boolean rotate) {
    state.refreshTokenRotation(rotate);
    return this;
  }

  @Override
  public OAuth2Bootstrap stateStore(StateStore store) {
    state.stateStore(store);
    return this;
  }

  @Override
  public OAuth2Bootstrap stateTtl(Duration ttl) {
    state.stateTtl(ttl);
    return this;
  }

  @Override
  public OAuth2Bootstrap refreshTokenFamilyStore(RefreshTokenFamilyStore store) {
    state.refreshTokenFamilyStore(store);
    return this;
  }

  @Override
  public OAuth2Bootstrap introspectionCacheTtl(Duration ttl) {
    state.introspectionCacheTtl(ttl);
    return this;
  }
}
