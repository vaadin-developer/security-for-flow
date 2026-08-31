package eu.jsentinel.jcustos.events.api;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

/**
 * Coarse security-domain classification of a {@link JSentinelEvent}.
 *
 * <p>Categories drive failure-strategy configuration
 * ({@code strategy(JSentinelEventCategory, ...)}) and consumer-side
 * filtering. They are intentionally domain-oriented, not transport- or
 * log-oriented (Konzept §181).
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public enum JSentinelEventCategory {

  /** Login, logout, password-reset, email-verification flows. */
  AUTHENTICATION,

  /** Permission / role checks and access decisions. */
  AUTHORIZATION,

  /** Session lifecycle (created, expired, revoked, stale). */
  SESSION,

  /** Policy evaluation and policy-driven denials. */
  POLICY,

  /** Role assignment, revocation and hierarchy changes. */
  ROLE,

  /** Remember-me / API-key / refresh-token lifecycle. */
  TOKEN,

  /** Trusted-device registration and revocation. */
  DEVICE,

  /** Rate-limit and brute-force throttling signals. */
  RATE_LIMIT,

  /** Administrative configuration changes. */
  ADMIN,

  /** Events explicitly modelled for audit consumption. */
  AUDIT,

  /** Technical, non-tenant-specific system signals. */
  SYSTEM,

  /** Envelope / bus integrity violations (replay, bad signature, sequence). */
  INTEGRITY
}
