/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.jsentinel.persistence.eclipsestore;

import com.svenruppert.jsentinel.accountlifecycle.EmailVerificationTokenRecord;
import com.svenruppert.jsentinel.accountlifecycle.PasswordResetTokenRecord;
import com.svenruppert.jsentinel.audit.AuditEnvelope;
import com.svenruppert.jsentinel.authentication.ApiKeyRecord;
import com.svenruppert.jsentinel.authentication.RefreshTokenRecord;
import com.svenruppert.jsentinel.authentication.RememberMeTokenRecord;
import com.svenruppert.jsentinel.authorization.api.roles.RoleAssignmentKey;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.bootstrap.BootstrapState;
import com.svenruppert.jsentinel.bruteforce.LoginAttemptKey;
import com.svenruppert.jsentinel.ratelimiting.RateLimitKey;
import com.svenruppert.jsentinel.session.JSentinelVersion;
import com.svenruppert.jsentinel.session.JSentinelVersionKey;
import com.svenruppert.jsentinel.session.SessionId;
import com.svenruppert.jsentinel.session.SessionRecord;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;

/**
 * Package-private container for everything an Eclipse-Store-backed
 * persistence layer needs to keep around.
 * <p>
 * Eclipse Store reaches the entire object graph from a single root
 * reference; the {@link EclipseStoreJSentinelStorage} lifecycle owns
 * the one and only instance of this class and hands it out to the
 * individual {@code EclipseStore*Store} adapters. Nothing outside
 * this module touches the root — the public API surface of the
 * module is the {@link EclipseStoreJSentinelStorage} facade plus the
 * Phase-2 store SPIs.
 *
 * <p>Plan exit criterion: <em>no public API type called
 * {@code JSentinelRoot}</em>. This class is package-private; its name
 * carries a precise prefix and the module suffix.
 *
 * <p>The fields are mutable {@link LinkedHashMap}/{@link
 * LinkedHashSet} instances so Eclipse Store can persist them in
 * place — the store adapters mutate them under the lifecycle's
 * write lock and call {@code manager.store(field)} after each
 * mutation.
 */
final class EclipseStoreJSentinelRoot {

  /** id → envelope (audit events). */
  final Map<String, AuditEnvelope> auditEnvelopes = new LinkedHashMap<>();

  /** session id → session record. */
  final Map<SessionId, SessionRecord> sessions = new LinkedHashMap<>();

  /** login attempt key → (failureCount, lastFailureAt). */
  final Map<LoginAttemptKey, LoginAttemptLedger> loginAttempts = new LinkedHashMap<>();

  /** role assignment key → role set. */
  final Map<RoleAssignmentKey, LinkedHashSet<RoleName>> roleAssignments = new LinkedHashMap<>();

  /** tenant → bootstrap state. */
  final Map<TenantId, BootstrapState> bootstrapStates = new LinkedHashMap<>();

  /** token hash → remember-me record. */
  final Map<String, RememberMeTokenRecord> rememberMeTokens = new LinkedHashMap<>();

  /** token hash → password-reset record. */
  final Map<String, PasswordResetTokenRecord> passwordResetTokens = new LinkedHashMap<>();

  /** token hash → email-verification record. */
  final Map<String, EmailVerificationTokenRecord> emailVerificationTokens = new LinkedHashMap<>();

  /** key hash → api-key record. */
  final Map<String, ApiKeyRecord> apiKeys = new LinkedHashMap<>();

  /** token hash → refresh-token record. */
  final Map<String, RefreshTokenRecord> refreshTokens = new LinkedHashMap<>();

  /** rate-limit key → ordered list of event instants. */
  final Map<RateLimitKey, LinkedHashSet<Instant>> rateLimitEvents = new LinkedHashMap<>();

  /** (tenant, subject) → current security version. */
  final Map<JSentinelVersionKey, JSentinelVersion> securityVersions = new LinkedHashMap<>();

  EclipseStoreJSentinelRoot() {
  }

  /**
   * Tiny package-private record that holds the
   * {@code LoginAttemptStore}'s per-key state. Kept here (alongside
   * the root) rather than in {@code security-core} because it is an
   * implementation detail of how this module stores the data;
   * {@code LoginAttemptStore} itself exposes only counter +
   * timestamp through behavioural API.
   *
   * @param count          accumulated failure count
   * @param lastFailureAt  most recent failure instant
   */
  record LoginAttemptLedger(int count, Instant lastFailureAt) {
  }
}
