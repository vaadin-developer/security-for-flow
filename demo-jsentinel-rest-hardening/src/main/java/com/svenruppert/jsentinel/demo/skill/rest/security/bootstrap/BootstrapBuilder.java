package com.svenruppert.jsentinel.demo.skill.rest.security.bootstrap;

import com.svenruppert.jsentinel.dx.rest.bootstrap.RestJSentinelBootstrap;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Helper that aggregates every registered {@link BootstrapExtension}
 * via {@link ServiceLoader}, sorts them by {@link BootstrapExtension#order()},
 * and applies them in a single {@code .audit(...)} / {@code .sessions(...)}
 * / {@code .credentials(...)} call on the fluent
 * {@code RestSecurity.bootstrap()} chain.
 */
public final class BootstrapBuilder {

  private BootstrapBuilder() {
  }

  public static RestJSentinelBootstrap apply(RestJSentinelBootstrap builder) {
    List<BootstrapExtension> extensions = new ArrayList<>();
    ServiceLoader.load(BootstrapExtension.class).forEach(extensions::add);
    extensions.sort(Comparator.comparingInt(BootstrapExtension::order));
    return builder
        .audit(a -> extensions.forEach(e -> e.contributeAudit(a)))
        .sessions(s -> extensions.forEach(e -> e.contributeSessions(s)))
        .credentials(c -> extensions.forEach(e -> e.contributeCredentials(c)));
  }
}
