package com.svenruppert.jsentinel.demo.skill.vaadin.security.bootstrap;

import com.svenruppert.jsentinel.dx.vaadin.bootstrap.VaadinJSentinelBootstrap;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Helper that aggregates every registered {@link BootstrapExtension}
 * via {@link ServiceLoader}, sorts them by {@link BootstrapExtension#order()},
 * and applies them in a single {@code .audit(...)} / {@code .sessions(...)}
 * / {@code .credentials(...)} call on the fluent
 * {@code VaadinSecurity.bootstrap()} chain.
 *
 * <p>This is the central seam that makes Layer 2 / Layer 3 / future
 * additive: any number of skills can each ship one extension; none
 * of them touches the entry-point listener.
 *
 * <p>Defaults are registered by {@link JSentinelBootstrapInitListener}'s
 * static initialiser before the first {@link #apply(VaadinJSentinelBootstrap)}
 * call.
 */
public final class BootstrapBuilder {

  private BootstrapBuilder() {
  }

  /**
   * Applies every registered {@link BootstrapExtension} to the
   * supplied builder. The single {@code .audit / .sessions / .credentials}
   * calls let multiple contributors stack their sub-config on the
   * same builder without resetting each other.
   *
   * @param builder a fresh fluent bootstrap chain (already configured
   *                with {@code authentication / authorization /
   *                loginRoute} etc.)
   * @return the same builder, for chaining {@code .install()}
   */
  public static VaadinJSentinelBootstrap apply(VaadinJSentinelBootstrap builder) {
    List<BootstrapExtension> extensions = new ArrayList<>();
    ServiceLoader.load(BootstrapExtension.class).forEach(extensions::add);
    extensions.sort(Comparator.comparingInt(BootstrapExtension::order));
    return builder
        .audit(a -> extensions.forEach(e -> e.contributeAudit(a)))
        .sessions(s -> extensions.forEach(e -> e.contributeSessions(s)))
        .credentials(c -> extensions.forEach(e -> e.contributeCredentials(c)));
  }
}
