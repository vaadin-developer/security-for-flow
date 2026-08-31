package eu.jsentinel.jcustos.monitoring.metrics;

/*-
 * #%L
 * jSentinel Monitoring — metrics, health and diagnostics export points
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
 * Single source of truth for the jSentinel metric-name catalog.
 *
 * <p>These names are API: dashboards, alert rules and retention
 * policies reference them literally, so renaming a constant's
 * <em>value</em> is a breaking change and follows the same SemVer
 * discipline as any other public contract. The nine
 * {@code security.eventbus.*} names are mandated verbatim by
 * Konzept-V00.80.00 (goal 9); the auth / session / audit names are
 * minted here.</p>
 *
 * <p>Each constant documents whether it is a <em>counter</em>
 * (cumulative, emitted via
 * {@link JSentinelMetricsPublisher#increment(String, long)}) or a
 * <em>gauge</em> (push-style snapshot, emitted via
 * {@link JSentinelMetricsPublisher#gauge(String, long)}), and where
 * the emission is expected to happen.</p>
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class JSentinelMetricNames {

  // --- event-bus names (Konzept-V00.80.00 goal 9, verbatim) ---

  /**
   * Counter — events accepted and published by the security event bus.
   * Emitted by the V00.80 {@code MetricsEventBusListener} bridge.
   */
  public static final String EVENTBUS_PUBLISHED_TOTAL          = "security.eventbus.published.total";

  /**
   * Counter — events rejected by the bus (producer policy, capacity,
   * validation). Emitted by the V00.80 {@code MetricsEventBusListener}
   * bridge.
   */
  public static final String EVENTBUS_REJECTED_TOTAL           = "security.eventbus.rejected.total";

  /**
   * Counter — replay attempts detected on the event bus. Emitted by
   * the V00.80 {@code MetricsEventBusListener} bridge.
   */
  public static final String EVENTBUS_REPLAY_DETECTED_TOTAL    = "security.eventbus.replay.detected.total";

  /**
   * Counter — per-producer sequence violations detected on the event
   * bus. Emitted by the V00.80 {@code MetricsEventBusListener} bridge.
   */
  public static final String EVENTBUS_SEQUENCE_VIOLATION_TOTAL = "security.eventbus.sequence.violation.total";

  /**
   * Counter — events whose signature failed verification. Emitted by
   * the V00.80 {@code MetricsEventBusListener} bridge.
   */
  public static final String EVENTBUS_SIGNATURE_INVALID_TOTAL  = "security.eventbus.signature.invalid.total";

  /**
   * Counter — events routed to the dead-letter store. Emitted by the
   * V00.80 {@code MetricsEventBusListener} bridge.
   */
  public static final String EVENTBUS_DEADLETTER_TOTAL         = "security.eventbus.deadletter.total";

  /**
   * Counter — listener invocations that threw. Emitted by the V00.80
   * {@code MetricsEventBusListener} bridge.
   */
  public static final String EVENTBUS_LISTENER_FAILURE_TOTAL   = "security.eventbus.listener.failure.total";

  /**
   * Gauge — currently open SSE event streams. Application-wired: push
   * {@code SseStreamHttpHandler.activeStreamCount()} via
   * {@link JSentinelMetricsPublisher#gauge(String, long)}.
   */
  public static final String EVENTBUS_SSE_CONNECTIONS_ACTIVE   = "security.eventbus.sse.connections.active";

  /**
   * Counter — SSE client reconnects. <strong>Reserved:</strong> no
   * framework emission hook exists yet; the name is stable API today,
   * the emission lands in a later release.
   */
  public static final String EVENTBUS_SSE_RECONNECTS_TOTAL     = "security.eventbus.sse.reconnects.total";

  // --- auth / session / audit names (minted in V00.80.00) ---

  /**
   * Counter — successful logins. Emitted by the V00.80
   * {@code MetricsEventBusListener} bridge.
   */
  public static final String AUTH_LOGIN_SUCCESS_TOTAL  = "security.auth.login.success.total";

  /**
   * Counter — failed login attempts. Emitted by the V00.80
   * {@code MetricsEventBusListener} bridge.
   */
  public static final String AUTH_LOGIN_FAILURE_TOTAL  = "security.auth.login.failure.total";

  /**
   * Counter — account lockouts triggered by the login-attempt policy.
   * Emitted by the V00.80 {@code MetricsEventBusListener} bridge.
   */
  public static final String AUTH_LOCKOUT_TOTAL        = "security.auth.lockout.total";

  /**
   * Counter — authorization denials (navigation, REST, method-level).
   * Emitted by the V00.80 {@code MetricsEventBusListener} bridge.
   */
  public static final String AUTHZ_DENIED_TOTAL        = "security.authz.denied.total";

  /**
   * Counter — sessions created. Emitted by the V00.80
   * {@code MetricsEventBusListener} bridge.
   */
  public static final String SESSION_CREATED_TOTAL     = "security.session.created.total";

  /**
   * Counter — sessions revoked (logout, admin revoke, drift
   * enforcement). Emitted by the V00.80
   * {@code MetricsEventBusListener} bridge.
   */
  public static final String SESSION_REVOKED_TOTAL     = "security.session.revoked.total";

  /**
   * Gauge — currently active sessions. Application-wired: push the
   * {@code SessionStore} size via
   * {@link JSentinelMetricsPublisher#gauge(String, long)}.
   */
  public static final String SESSION_ACTIVE            = "security.session.active";

  /**
   * Gauge — audit-store backlog. Application-wired: push the
   * {@code RingBufferAuditSink} size relative to its capacity via
   * {@link JSentinelMetricsPublisher#gauge(String, long)}.
   */
  public static final String AUDIT_STORE_LAG           = "security.audit.store.lag";

  private JSentinelMetricNames() {
  }
}
