/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.propagation.diagnostics;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
import eu.jsentinel.jcustos.credential.propagation.ThreadSafeTokenCredentialStore;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticContributor;
import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticReportBuilder;
import eu.jsentinel.jcustos.dx.diagnostics.ServiceWarning;

import java.util.Optional;

/**
 * V00.74 propagation diagnostics. Surfaces the documented warning
 * codes (Konzept §13.2) about the runtime propagation surface.
 *
 * <p>Rules emitted:
 * <ul>
 *   <li>{@code propagation/missing-credential-store} — no SPI store
 *       registered and no {@code .propagation(p -> p.credentialStore(...))}
 *       chain.</li>
 *   <li>{@code propagation/store-not-thread-safe} — INFO when the
 *       registered store lacks the {@link ThreadSafeTokenCredentialStore}
 *       marker.</li>
 * </ul>
 *
 * Wrapper-presence checks (the {@code propagation/wrapper-without-*}
 * codes) live in the wrapper-index-driven report and stay out of this
 * contributor.
 *
 * @since 00.74.00
 */
@JCustosAutoService(DiagnosticContributor.class)
public final class PropagationDiagnosticContributor implements DiagnosticContributor {

  /** ServiceLoader requires a public no-arg constructor. */
  public PropagationDiagnosticContributor() {
  }

  @Override
  public String id() {
    return "propagation";
  }

  @Override
  public void contribute(DiagnosticReportBuilder builder) {
    try {
      Optional<TokenCredentialStore> store = JCustosServiceResolver.findTokenCredentialStore();
      if (store.isEmpty()) {
        builder.addWarning(new ServiceWarning(
            "propagation/missing-credential-store",
            "No TokenCredentialStore is registered.",
            "Register an adapter default via @JCustosAutoService or pass an explicit "
                + "store via .propagation(p -> p.credentialStore(...))."));
        return;
      }
      if (!(store.get() instanceof ThreadSafeTokenCredentialStore)) {
        builder.addWarning(new ServiceWarning(
            "propagation/store-not-thread-safe",
            "Registered TokenCredentialStore '" + store.get().getClass().getName()
                + "' does not carry the ThreadSafeTokenCredentialStore marker.",
            "If your runtime is single-thread (Vaadin per UI) this is fine; multi-thread "
                + "REST / Standalone setups should use a ThreadSafe store."));
      }
    } catch (RuntimeException e) {
      builder.addWarning(new ServiceWarning(
          "propagation/rule-failed",
          "propagation diagnostic failed: " + e.getClass().getSimpleName() + ": "
              + e.getMessage(),
          "Inspect JCustosServiceResolver state."));
    }
  }
}
