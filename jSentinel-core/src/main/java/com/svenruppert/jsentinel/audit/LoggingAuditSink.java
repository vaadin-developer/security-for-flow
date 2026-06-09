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
package com.svenruppert.jsentinel.audit;

import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * {@link AuditSink} that writes a single
 * {@link java.util.logging.Logger Logger} line per event at
 * {@link Level#INFO INFO} level. Never throws.
 * <p>
 * The line format is intentionally compact and stable so it can be
 * grepped from a deployment log: {@code AUDIT type=… field=value …}.
 */
public final class LoggingAuditSink implements AuditSink {

  private static final Logger DEFAULT_LOGGER =
      Logger.getLogger("com.svenruppert.jsentinel.audit");

  private final Logger logger;

  public LoggingAuditSink() {
    this(DEFAULT_LOGGER);
  }

  public LoggingAuditSink(Logger logger) {
    this.logger = Objects.requireNonNull(logger, "logger");
  }

  @Override
  public void accept(AuditEvent event) {
    if (event == null) return;
    try {
      logger.log(Level.INFO, format(event));
    } catch (RuntimeException ignored) {
      // sinks must never throw
    }
  }

  private static String format(AuditEvent event) {
    StringBuilder sb = new StringBuilder("AUDIT ");
    sb.append("type=").append(event.getClass().getSimpleName());
    switch (event) {
      case LoginSucceeded e -> appendLogin(sb, e.username(), e.clientAddress(), e.sessionId());
      case LoginFailed e -> {
        appendLogin(sb, e.username(), e.clientAddress(), null);
        appendField(sb, "reason", e.reason());
      }
      case LogoutPerformed e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "session", e.sessionId());
        appendField(sb, "scope", e.scope().name());
      }
      case AccessGranted e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "route", e.route());
      }
      case AccessDenied e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "route", e.route());
        appendField(sb, "reason", e.reason());
      }
      case ActionDenied e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "action", e.action());
      }
      case BruteForceLimitReached e -> {
        appendLogin(sb, e.username(), e.clientAddress(), null);
        appendField(sb, "failedAttempts", String.valueOf(e.failedAttempts()));
        appendField(sb, "lockoutSeconds",
            String.valueOf(e.lockoutDuration().toSeconds()));
      }
      case SessionCreated e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "session", e.sessionId());
      }
      case SessionExpired e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "session", e.sessionId());
        appendField(sb, "reason", e.reason());
      }
      case SessionInvalidated e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "session", e.sessionId());
        appendField(sb, "reason", e.reason());
      }
      case RoleAssigned e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "role", e.role());
        appendField(sb, "by", e.assignedBy());
      }
      case RoleRevoked e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "role", e.role());
        appendField(sb, "by", e.revokedBy());
      }
      case BootstrapAdminCreated e -> {
        appendField(sb, "username", e.username());
        appendField(sb, "client", e.clientAddress());
      }
      case BootstrapTokenRejected e -> {
        appendField(sb, "reason", e.reason());
        appendField(sb, "client", e.clientAddress());
      }
      case UserCreated e -> {
        appendField(sb, "username", e.username());
        appendField(sb, "role", e.role());
        appendField(sb, "by", e.createdBy());
      }
      case UserDeleted e -> {
        appendField(sb, "username", e.username());
        appendField(sb, "by", e.deletedBy());
      }
      case PolicyEvaluated e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "policy", e.policyName());
        appendField(sb, "decision", e.decision());
        appendField(sb, "reason", e.reason());
      }
      case StepUpChallenged e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "route", e.route());
        appendField(sb, "method", e.method());
        appendField(sb, "reason", e.reason());
      }
      case SessionStale e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "session", e.sessionId());
        appendField(sb, "route", e.route());
        appendField(sb, "snapshot", String.valueOf(e.snapshotVersion()));
        appendField(sb, "current", String.valueOf(e.currentVersion()));
      }
      case PasswordResetRequested e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "tokenHash", e.tokenHash());
      }
      case PasswordResetCompleted e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "tokenHash", e.tokenHash());
      }
      case EmailVerificationRequested e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "email", e.email());
        appendField(sb, "tokenHash", e.tokenHash());
      }
      case EmailVerified e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "email", e.email());
        appendField(sb, "tokenHash", e.tokenHash());
      }
      case ApiKeyUsed e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "keyName", e.keyName());
        appendField(sb, "keyHash", e.keyHash());
      }
      case ApiKeyDenied e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "keyHash", e.keyHash());
        appendField(sb, "reason", e.reason());
      }
      case TokenRotated e -> {
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "oldHash", e.oldHash());
        appendField(sb, "newHash", e.newHash());
      }
      case RateLimitExceeded e -> {
        appendField(sb, "scope", e.scope());
        appendField(sb, "subject", e.subjectId());
        appendField(sb, "limit", String.valueOf(e.limit()));
        appendField(sb, "windowSeconds", String.valueOf(e.window().toSeconds()));
        appendField(sb, "eventsInWindow", String.valueOf(e.eventsInWindow()));
      }
      case CredentialVerificationSucceeded e -> {
        appendField(sb, "user", e.username());
        appendField(sb, "client", e.clientAddress());
        appendField(sb, "algorithm", e.algorithm());
        appendField(sb, "provider", e.providerId());
        appendField(sb, "policyVersion", String.valueOf(e.policyVersion()));
        appendField(sb, "pepper", String.valueOf(e.pepperKeyIdPresent()));
        appendField(sb, "rehashRequired", String.valueOf(e.rehashRequired()));
      }
      case CredentialVerificationFailed e -> {
        appendField(sb, "user", e.username());
        appendField(sb, "client", e.clientAddress());
        appendField(sb, "internalReason", e.internalAuditEventType().name());
      }
      case CredentialRehashed e -> {
        appendField(sb, "user", e.username());
        appendField(sb, "from", e.fromAlgorithm());
        appendField(sb, "to", e.toAlgorithm());
        appendField(sb, "reason", e.reason().name());
        appendField(sb, "targetPolicyVersion",
            String.valueOf(e.targetPolicyVersion()));
      }
      case CredentialStatusChanged e -> {
        appendField(sb, "user", e.username());
        appendField(sb, "from", e.fromStatus().name());
        appendField(sb, "to", e.toStatus().name());
        appendField(sb, "reason", e.reason());
      }
    }
    return sb.toString();
  }

  private static void appendLogin(
      StringBuilder sb, String username, String clientAddress, String sessionId) {
    appendField(sb, "user", username);
    appendField(sb, "client", clientAddress);
    appendField(sb, "session", sessionId);
  }

  private static void appendField(StringBuilder sb, String key, String value) {
    if (value == null) return;
    sb.append(' ').append(key).append('=').append(value);
  }
}
