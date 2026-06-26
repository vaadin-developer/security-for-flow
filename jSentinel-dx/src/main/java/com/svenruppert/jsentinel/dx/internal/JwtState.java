package com.svenruppert.jsentinel.dx.internal;

import com.svenruppert.jsentinel.jwt.api.AlgorithmAllowList;
import com.svenruppert.jsentinel.jwt.api.AlgorithmProfile;
import com.svenruppert.jsentinel.jwt.api.JwtValidator;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Sub-aggregate of {@link BootstrapState} holding everything the {@code .jwt(...)}
 * sub-builder records. Internal — consumed by the adapter-DX {@code install()}
 * paths via {@code AbstractJSentinelBootstrap.applyJwtConfiguration(...)}.
 *
 * @since 00.76.00
 */
public final class JwtState {

  private JwtValidator validator;
  private URI jwksUri;
  private AlgorithmProfile profile;
  private AlgorithmAllowList allowList;
  private String issuer;
  private final Set<String> audiences = new LinkedHashSet<>();
  private Duration clockSkew;
  private String tokenType;

  public JwtValidator validator() {
    return validator;
  }

  public void validator(JwtValidator v) {
    this.validator = v;
  }

  public URI jwksUri() {
    return jwksUri;
  }

  public void jwksUri(URI uri) {
    this.jwksUri = uri;
  }

  public AlgorithmProfile profile() {
    return profile;
  }

  public void profile(AlgorithmProfile p) {
    this.profile = p;
  }

  public AlgorithmAllowList allowList() {
    return allowList;
  }

  public void allowList(AlgorithmAllowList a) {
    this.allowList = a;
  }

  public String issuer() {
    return issuer;
  }

  public void issuer(String i) {
    this.issuer = i;
  }

  public Set<String> audiences() {
    return Set.copyOf(audiences);
  }

  public void addAudiences(String... values) {
    for (String v : values) {
      if (v != null) {
        audiences.add(v);
      }
    }
  }

  public Duration clockSkew() {
    return clockSkew;
  }

  public void clockSkew(Duration d) {
    this.clockSkew = d;
  }

  public String tokenType() {
    return tokenType;
  }

  public void tokenType(String t) {
    this.tokenType = t;
  }

  /** @return true if the sub-builder recorded anything (an empty {@code .jwt(j -> {})} is a no-op). */
  public boolean hasAnySelection() {
    return validator != null || jwksUri != null || profile != null || allowList != null
        || issuer != null || !audiences.isEmpty() || clockSkew != null || tokenType != null;
  }
}
