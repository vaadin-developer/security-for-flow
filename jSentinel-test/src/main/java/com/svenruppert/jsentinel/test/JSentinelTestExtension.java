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
package com.svenruppert.jsentinel.test;

import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.reflect.AnnotatedElement;

/**
 * JUnit 5 extension that calls
 * {@link JSentinelServiceResolver#resetAll()} before <em>and</em>
 * after every test, ensuring SPI caches, subject stores, and the
 * policy / resource registries start clean for each test method.
 *
 * <p>V00.74: also reads {@link WithJSentinelSubject} annotations on
 * the test method (preferred) or test class (fallback). When
 * present, the extension builds a {@link JSentinelTestFixture} with
 * the declared roles / permissions and binds the subject before the
 * test method runs. The fixture is closed automatically after the
 * test method completes (or fails).
 *
 * <p>Activate by annotating the test class with
 * {@code @ExtendWith(JSentinelTestExtension.class)}; the extension is
 * stateless so multiple test classes share it safely.
 *
 * <pre>
 *   &#64;ExtendWith(JSentinelTestExtension.class)
 *   class DocumentServiceTest {
 *
 *     &#64;Test
 *     &#64;WithJSentinelSubject(roles = "ROLE_ADMIN")
 *     void onlyAdminsCanDelete() {
 *       documentService.delete(doc);  // passes
 *     }
 *   }
 * </pre>
 */
public final class JSentinelTestExtension implements BeforeEachCallback, AfterEachCallback {

  private static final ExtensionContext.Namespace NS =
      ExtensionContext.Namespace.create(JSentinelTestExtension.class);

  /** Creates the extension. */
  public JSentinelTestExtension() {
  }

  @Override
  public void beforeEach(ExtensionContext context) {
    JSentinelServiceResolver.resetAll();
    if (context == null) {
      return;
    }
    WithJSentinelSubject annotation = findAnnotation(context);
    if (annotation != null) {
      JSentinelTestFixture.Builder builder = JSentinelTestFixture.builder()
          .subject(annotation.value());
      if (!annotation.displayName().isEmpty()) {
        builder.displayName(annotation.displayName());
      }
      for (String role : annotation.roles()) {
        builder.role(role);
      }
      for (String perm : annotation.permissions()) {
        builder.permission(perm);
      }
      JSentinelTestFixture fixture = builder.build();
      context.getStore(NS).put(JSentinelTestFixture.class, fixture);
    }
  }

  @Override
  public void afterEach(ExtensionContext context) {
    if (context != null) {
      JSentinelTestFixture fixture = context.getStore(NS)
          .remove(JSentinelTestFixture.class, JSentinelTestFixture.class);
      if (fixture != null) {
        fixture.close();
      }
    }
    JSentinelServiceResolver.resetAll();
  }

  private static WithJSentinelSubject findAnnotation(ExtensionContext context) {
    return context.getElement()
        .map(JSentinelTestExtension::readAnnotation)
        .filter(a -> a != null)
        .orElseGet(() -> context.getTestClass()
            .map(JSentinelTestExtension::readAnnotation)
            .orElse(null));
  }

  private static WithJSentinelSubject readAnnotation(AnnotatedElement element) {
    return element.getAnnotation(WithJSentinelSubject.class);
  }
}
