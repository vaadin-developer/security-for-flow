/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.jsentinel.credential.propagation;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

/**
 * Marker for {@link TokenCredentialStore} implementations that are safe
 * to use from multiple threads. The REST and Standalone adapter
 * defaults carry this marker (per-thread {@link ThreadLocal} slot, no
 * shared state). The Vaadin default does <strong>not</strong> — Vaadin's
 * session is single-thread per UI; background-thread access is an
 * application bug, not a framework concern.
 *
 * <p>{@code PropagationDiagnosticContributor} (V00.74 Prompt 018)
 * surfaces a {@code propagation/store-not-thread-safe} INFO code when a
 * consumer-supplied store on a REST / Standalone bootstrap lacks this
 * marker.
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public interface ThreadSafeTokenCredentialStore extends TokenCredentialStore {
}
