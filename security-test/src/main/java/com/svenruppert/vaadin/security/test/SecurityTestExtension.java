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
package com.svenruppert.vaadin.security.test;

import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * JUnit 5 extension that calls
 * {@link SecurityServiceResolver#resetAll()} before <em>and</em>
 * after every test, ensuring SPI caches, subject stores, and the
 * policy / resource registries start clean for each test method.
 *
 * <p>Activate by annotating the test class with
 * {@code @ExtendWith(SecurityTestExtension.class)}; the extension is
 * stateless so multiple test classes share it safely.
 */
public final class SecurityTestExtension implements BeforeEachCallback, AfterEachCallback {

  /** Creates the extension. */
  public SecurityTestExtension() {
  }

  @Override
  public void beforeEach(ExtensionContext context) {
    SecurityServiceResolver.resetAll();
  }

  @Override
  public void afterEach(ExtensionContext context) {
    SecurityServiceResolver.resetAll();
  }
}
