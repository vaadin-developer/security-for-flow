package com.svenruppert.jsentinel.events.store;

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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;

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
@ExperimentalJSentinelApi
public record JSentinelEventDeadLetter(
    DeadLetterId id,
    SignedJSentinelEventEnvelope envelope,
    RejectionReason reason,
    Instant recordedAt
) {

  public JSentinelEventDeadLetter {
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
  public static JSentinelEventDeadLetter of(SignedJSentinelEventEnvelope envelope,
      RejectionReason reason, Instant recordedAt) {
    return new JSentinelEventDeadLetter(DeadLetterId.random(), envelope, reason, recordedAt);
  }
}
