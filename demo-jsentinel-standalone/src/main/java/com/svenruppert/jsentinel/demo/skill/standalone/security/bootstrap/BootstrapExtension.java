package com.svenruppert.jsentinel.demo.skill.standalone.security.bootstrap;

import com.svenruppert.jsentinel.dx.bootstrap.AuditBootstrap;
import com.svenruppert.jsentinel.dx.bootstrap.CredentialBootstrap;
import com.svenruppert.jsentinel.dx.bootstrap.SessionBootstrap;

/**
 * Project-local SPI for additive bootstrap configuration.
 *
 * <p>Layer 1 (this skill) defines the contract; higher layers ship
 * implementations registered via
 * {@code META-INF/services/{@value #SERVICE_NAME}}.
 *
 * <p>{@link BootstrapBuilder#apply(Object)} loads every registered
 * implementation through {@link java.util.ServiceLoader}, sorts by
 * {@link #order()}, and invokes the three {@code contribute*} hooks
 * inside a single {@code .audit / .sessions / .credentials} call on
 * the fluent {@code StandaloneSecurity.bootstrap()} chain — multiple
 * layers can configure the same sub-aspect without overwriting each
 * other.
 */
public interface BootstrapExtension {

  String SERVICE_NAME = "com.svenruppert.jsentinel.demo.skill.standalone.security.bootstrap.BootstrapExtension";

  default void contributeAudit(AuditBootstrap a) {
  }

  default void contributeSessions(SessionBootstrap s) {
  }

  default void contributeCredentials(CredentialBootstrap c) {
  }

  default int order() {
    return 0;
  }
}
