package com.svenruppert.jsentinel.events.rest;

/*-
 * #%L
 * jSentinel Events — REST / SSE bridge
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

/**
 * Short, generic response bodies the publish endpoint returns per verification
 * outcome (Konzept §117). Kept in one place so {@link EventPublishService} and
 * its tests share a single source of truth and the wording cannot drift apart.
 * Bodies are intentionally generic — no internals, no stack traces.
 *
 * @since 00.75.00
 */
final class EventPublishBodies {

  static final String ACCEPTED = "Accepted";
  static final String MALFORMED_ENVELOPE = "Malformed envelope";
  static final String INVALID_SIGNATURE = "Invalid signature";
  static final String PAYLOAD_HASH_MISMATCH = "Payload hash mismatch";
  static final String UNKNOWN_KEY = "Unknown key";
  static final String KEY_REVOKED = "Key revoked";
  static final String EXPIRED = "Expired";
  static final String REPLAY_DETECTED = "Replay detected";
  static final String SEQUENCE_VIOLATION = "Sequence violation";
  static final String PRODUCER_NOT_ALLOWED = "Producer not allowed";

  private EventPublishBodies() {
  }
}