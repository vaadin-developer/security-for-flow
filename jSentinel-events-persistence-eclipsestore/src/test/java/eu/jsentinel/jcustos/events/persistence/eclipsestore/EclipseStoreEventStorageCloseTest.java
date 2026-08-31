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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@DisplayName("EclipseStoreEventStorage.close() is idempotent (R04)")
class EclipseStoreEventStorageCloseTest {

  @TempDir
  Path tempDir;

  @Test
  @DisplayName("a second close() is a no-op, not a hit on an already-shut manager")
  void doubleCloseIsNoop() {
    EclipseStoreEventStorage storage = EclipseStoreEventStorage.openAt(tempDir);
    storage.close();
    // R04: the destroy listener + the JVM shutdown hook can both fire — the
    // second close must be a genuine no-op.
    assertDoesNotThrow(storage::close);
  }
}
