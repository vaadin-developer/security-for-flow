package eu.jsentinel.jcustos.events.store;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;

import java.time.Instant;
import java.util.Objects;

/**
 * A structured dead-letter record: the rejected envelope, the reason and when
 * it was recorded (Konzept §736).
 *
 * @param id the dead-letter identity
 * @param envelope the rejected envelope
 * @param reason why it was rejected
 * @param recordedAt when it was recorded
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public record JCustosEventDeadLetter(
    DeadLetterId id,
    SignedJCustosEventEnvelope envelope,
    RejectionReason reason,
    Instant recordedAt
) {

  public JCustosEventDeadLetter {
    Objects.requireNonNull(id, "id");
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(reason, "reason");
    Objects.requireNonNull(recordedAt, "recordedAt");
  }

  /**
   * Factory assigning a random {@link DeadLetterId}.
   *
   * @param envelope the rejected envelope
   * @param reason the rejection reason
   * @param recordedAt the recording instant
   * @return a new dead-letter record
   */
  public static JCustosEventDeadLetter of(SignedJCustosEventEnvelope envelope,
      RejectionReason reason, Instant recordedAt) {
    return new JCustosEventDeadLetter(DeadLetterId.random(), envelope, reason, recordedAt);
  }
}
