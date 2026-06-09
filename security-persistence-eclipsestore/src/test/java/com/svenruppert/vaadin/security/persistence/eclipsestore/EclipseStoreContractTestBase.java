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
package com.svenruppert.vaadin.security.persistence.eclipsestore;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

/**
 * Boilerplate for every contract test that runs an Eclipse-Store-
 * backed adapter: a fresh {@code @TempDir} per test method, a
 * matching {@link EclipseStoreJSentinelStorage} started in
 * {@code @BeforeEach}, and a clean shutdown in {@code @AfterEach}.
 * <p>
 * Concrete contract tests extend this class <strong>and</strong>
 * implement the corresponding {@code …Contract} interface from
 * {@code security-persistence-testkit}; the contract's
 * {@code newStore()} factory delegates into {@link #storage}.
 */
abstract class EclipseStoreContractTestBase {

  @TempDir
  Path tempDir;

  protected EclipseStoreJSentinelStorage storage;

  @BeforeEach
  void startStorage() {
    storage = EclipseStoreJSentinelStorage.openAt(tempDir);
  }

  @AfterEach
  void closeStorage() {
    if (storage != null) {
      storage.close();
    }
  }
}
