package com.svenruppert.jsentinel.events.testkit;

/*-
 * #%L
 * jSentinel Events — Contract testkit
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
import com.svenruppert.jsentinel.events.store.JSentinelEventDeadLetter;
import com.svenruppert.jsentinel.events.store.JSentinelEventDeadLetterStore;
import com.svenruppert.jsentinel.events.store.RejectionReason;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reusable contract for {@link JSentinelEventDeadLetterStore} implementations.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
@DisplayName("JSentinelEventDeadLetterStore — contract")
public interface DeadLetterStoreContract {

  JSentinelEventDeadLetterStore newDeadLetterStore();

  @Test
  @DisplayName("stored dead letters appear in findOpen, oldest first")
  default void storeAndFindOpen() {
    JSentinelEventDeadLetterStore store = newDeadLetterStore();
    store.store(JSentinelEventDeadLetter.of(
        TestkitEnvelopes.envelope("a"), RejectionReason.INVALID_SIGNATURE, TestkitEnvelopes.AT));
    store.store(JSentinelEventDeadLetter.of(
        TestkitEnvelopes.envelope("b"), RejectionReason.REPLAY_DETECTED, TestkitEnvelopes.AT));
    List<JSentinelEventDeadLetter> open = store.findOpen(10);
    assertEquals(2, open.size());
    assertEquals(RejectionReason.INVALID_SIGNATURE, open.get(0).reason());
    assertEquals(RejectionReason.REPLAY_DETECTED, open.get(1).reason());
  }

  @Test
  @DisplayName("markResolved removes a record from findOpen")
  default void markResolved() {
    JSentinelEventDeadLetterStore store = newDeadLetterStore();
    JSentinelEventDeadLetter dl = JSentinelEventDeadLetter.of(
        TestkitEnvelopes.envelope("a"), RejectionReason.SEQUENCE_VIOLATION, TestkitEnvelopes.AT);
    store.store(dl);
    store.markResolved(dl.id());
    assertTrue(store.findOpen(10).isEmpty());
  }

  @Test
  @DisplayName("findOpen honours the limit")
  default void limit() {
    JSentinelEventDeadLetterStore store = newDeadLetterStore();
    for (int i = 0; i < 5; i++) {
      store.store(JSentinelEventDeadLetter.of(
          TestkitEnvelopes.envelope("e" + i), RejectionReason.EXPIRED, TestkitEnvelopes.AT));
    }
    assertEquals(3, store.findOpen(3).size());
  }
}
