package eu.jsentinel.jcustos.audit.integrity.persistence.eclipsestore;

/*-
 * #%L
 * jSentinel Audit Integrity — Eclipse-Store persistence
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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

/** Opens a fresh storage per test method and closes it afterwards. */
abstract class EclipseStoreAuditChainStorageTestBase {

  @TempDir
  Path tempDir;

  EclipseStoreAuditChainStorage storage;

  @BeforeEach
  void openStorage() {
    storage = EclipseStoreAuditChainStorage.openAt(tempDir);
  }

  @AfterEach
  void closeStorage() {
    if (storage != null) {
      storage.close();
    }
  }
}
