package eu.jsentinel.jcustos.events.persistence.eclipsestore;

/*-
 * #%L
 * jSentinel Events — Eclipse-Store persistence
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

import eu.jsentinel.jcustos.events.store.DeadLetterId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("EclipseStoreDeadLetterStore — JS-SEC-052 no unbounded resolved-id set")
class EclipseStoreDeadLetterStoreResolveTest extends EclipseStoreEventStorageTestBase {

  @Test
  @DisplayName("JS-SEC-052: markResolved drops the heavy record and never grows a resolved-id set")
  void markResolvedDoesNotGrowResolvedSet() {
    EclipseStoreDeadLetterStore store = new EclipseStoreDeadLetterStore(storage);
    for (int i = 0; i < 50; i++) {
      store.markResolved(new DeadLetterId("dl-" + i));
    }
    assertTrue(storage.root().resolvedDeadLetters.isEmpty(),
        "the resolved-id set must not accumulate, was " + storage.root().resolvedDeadLetters.size());
  }
}
