package eu.jsentinel.jcustos.events.testkit;

/*-
 * #%L
 * jCustos Events — Contract testkit
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.store.JCustosEventDeadLetter;
import eu.jsentinel.jcustos.events.store.JCustosEventDeadLetterStore;
import eu.jsentinel.jcustos.events.store.RejectionReason;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reusable contract for {@link JCustosEventDeadLetterStore} implementations.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
@DisplayName("JCustosEventDeadLetterStore — contract")
public interface DeadLetterStoreContract {

  JCustosEventDeadLetterStore newDeadLetterStore();

  @Test
  @DisplayName("stored dead letters appear in findOpen, oldest first")
  default void storeAndFindOpen() {
    JCustosEventDeadLetterStore store = newDeadLetterStore();
    store.store(JCustosEventDeadLetter.of(
        TestkitEnvelopes.envelope("a"), RejectionReason.INVALID_SIGNATURE, TestkitEnvelopes.AT));
    store.store(JCustosEventDeadLetter.of(
        TestkitEnvelopes.envelope("b"), RejectionReason.REPLAY_DETECTED, TestkitEnvelopes.AT));
    List<JCustosEventDeadLetter> open = store.findOpen(10);
    assertEquals(2, open.size());
    assertEquals(RejectionReason.INVALID_SIGNATURE, open.get(0).reason());
    assertEquals(RejectionReason.REPLAY_DETECTED, open.get(1).reason());
  }

  @Test
  @DisplayName("markResolved removes a record from findOpen")
  default void markResolved() {
    JCustosEventDeadLetterStore store = newDeadLetterStore();
    JCustosEventDeadLetter dl = JCustosEventDeadLetter.of(
        TestkitEnvelopes.envelope("a"), RejectionReason.SEQUENCE_VIOLATION, TestkitEnvelopes.AT);
    store.store(dl);
    store.markResolved(dl.id());
    assertTrue(store.findOpen(10).isEmpty());
  }

  @Test
  @DisplayName("findOpen honours the limit")
  default void limit() {
    JCustosEventDeadLetterStore store = newDeadLetterStore();
    for (int i = 0; i < 5; i++) {
      store.store(JCustosEventDeadLetter.of(
          TestkitEnvelopes.envelope("e" + i), RejectionReason.EXPIRED, TestkitEnvelopes.AT));
    }
    assertEquals(3, store.findOpen(3).size());
  }
}
