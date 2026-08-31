package eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap;

import eu.jsentinel.jcustos.dx.bootstrap.AuditBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.CredentialBootstrap;
import eu.jsentinel.jcustos.dx.bootstrap.SessionBootstrap;

/**
 * Project-local SPI for additive bootstrap configuration.
 *
 * <p>Layer-1 (this skill) defines the contract. Higher layers
 * ({@code jsentinel-vaadin-persistence}, {@code jsentinel-vaadin-hardening},
 * future {@code -mfa} / {@code -multi-tenant} etc.) each ship one
 * implementation registered via
 * {@code META-INF/services/{@value #SERVICE_NAME}}.
 *
 * <p>{@link BootstrapBuilder#apply(Object)} loads every registered
 * implementation through {@link java.util.ServiceLoader}, sorts by
 * {@link #order()}, and invokes the three {@code contribute*}
 * hooks inside a single {@code .audit(...)} / {@code .sessions(...)}
 * / {@code .credentials(...)} call on the fluent
 * {@code VaadinSecurity.bootstrap()} chain — so multiple layers can
 * configure the same sub-aspect without overwriting each other.
 *
 * <p>All three hooks have an empty default — a layer overrides only
 * the sub-aspects it cares about.
 */
public interface BootstrapExtension {

  /**
   * The SPI service-file name for this interface. Skills that ship a
   * {@link BootstrapExtension} write a file at
   * {@code src/main/resources/META-INF/services/} + this constant.
   */
  String SERVICE_NAME = "eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap.BootstrapExtension";

  /** Adds audit-related configuration. */
  default void contributeAudit(AuditBootstrap a) {
  }

  /** Adds session-related configuration. */
  default void contributeSessions(SessionBootstrap s) {
  }

  /** Adds credential / hashing configuration. */
  default void contributeCredentials(CredentialBootstrap c) {
  }

  /**
   * Order in which extensions are invoked. Lower runs first; ties
   * are broken in service-loader-discovery order (effectively
   * undefined). Layer 1 defaults: 0. Layer 2 (persistence): 10.
   * Layer 3 (hardening): 20. Leaves room for finer interleaving.
   */
  default int order() {
    return 0;
  }
}
