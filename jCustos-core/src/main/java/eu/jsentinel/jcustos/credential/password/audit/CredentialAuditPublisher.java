/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.password.audit;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.CredentialRehashed;
import eu.jsentinel.jcustos.audit.CredentialVerificationFailed;
import eu.jsentinel.jcustos.audit.CredentialVerificationSucceeded;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.RehashDecision;
import eu.jsentinel.jcustos.credential.password.RehashReason;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

/**
 * Translates {@link CredentialVerificationResult}s into the new
 * credential audit events and pushes them through
 * {@link JCustosAuditService}.
 *
 * <p>The publisher <strong>never propagates</strong> audit-sink
 * exceptions to the caller (CWE-778 / CWE-693): publishing is
 * defence-in-depth, not a hard precondition. Sink failures are
 * swallowed so a misconfigured audit backend cannot turn into a
 * denial-of-service against successful logins.</p>
 */
public final class CredentialAuditPublisher implements HasLogger {

  private final JCustosAuditService auditService;
  private final Clock clock;

  public CredentialAuditPublisher(JCustosAuditService auditService) {
    this(auditService, Clock.systemUTC());
  }

  public CredentialAuditPublisher(
      JCustosAuditService auditService, Clock clock) {
    this.auditService = Objects.requireNonNull(auditService, "auditService");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Publishes the appropriate audit event for the supplied verification
   * outcome.
   */
  public void publish(
      String username,
      String clientAddress,
      CredentialVerificationResult result,
      RehashDecision rehashDecision) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(result, "result");
    Objects.requireNonNull(rehashDecision, "rehashDecision");

    Instant now = Instant.now(clock);
    if (result instanceof CredentialVerificationResult.Verified verified) {
      safePublish(new CredentialVerificationSucceeded(
          now,
          username,
          clientAddress,
          verified.algorithm(),
          verified.providerId(),
          verified.policyVersion(),
          verified.pepperKeyId().isPresent(),
          rehashDecision instanceof RehashDecision.Required));
    } else if (result instanceof CredentialVerificationResult.Failed failed) {
      safePublish(new CredentialVerificationFailed(
          now,
          username,
          clientAddress,
          failed.internalAuditEventType()));
    }
  }

  /**
   * Publishes a {@link CredentialRehashed} event after a successful
   * compare-and-swap upgrade in the credential store.
   */
  public void publishRehash(
      String username,
      String fromAlgorithm,
      String toAlgorithm,
      RehashReason reason,
      int targetPolicyVersion) {
    Objects.requireNonNull(username, "username");
    safePublish(new CredentialRehashed(
        Instant.now(clock),
        username,
        fromAlgorithm,
        toAlgorithm,
        reason,
        targetPolicyVersion));
  }

  private void safePublish(eu.jsentinel.jcustos.audit.AuditEvent event) {
    try {
      auditService.publish(event);
    } catch (RuntimeException ex) {
      // R036: never let audit-sink failures break the login path (CWE-778), but
      // a swallowed failure is a security-relevant blind spot — log it at WARN.
      // No secrets in the message: only the event type.
      logger().warn(
          "audit/sink-failure: credential audit event {} not published",
          event.getClass().getSimpleName(), ex);
    }
  }
}
