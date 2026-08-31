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
package eu.jsentinel.jcustos.test;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.reflect.AnnotatedElement;

/**
 * JUnit 5 extension that calls
 * {@link JCustosServiceResolver#resetAll()} before <em>and</em>
 * after every test, ensuring SPI caches, subject stores, and the
 * policy / resource registries start clean for each test method.
 *
 * <p>V00.74: also reads {@link WithJCustosSubject} annotations on
 * the test method (preferred) or test class (fallback). When
 * present, the extension builds a {@link JCustosTestFixture} with
 * the declared roles / permissions and binds the subject before the
 * test method runs. The fixture is closed automatically after the
 * test method completes (or fails).
 *
 * <p>Activate by annotating the test class with
 * {@code @ExtendWith(JCustosTestExtension.class)}; the extension is
 * stateless so multiple test classes share it safely.
 *
 * <pre>
 *   &#64;ExtendWith(JCustosTestExtension.class)
 *   class DocumentServiceTest {
 *
 *     &#64;Test
 *     &#64;WithJCustosSubject(roles = "ROLE_ADMIN")
 *     void onlyAdminsCanDelete() {
 *       documentService.delete(doc);  // passes
 *     }
 *   }
 * </pre>
 */
public final class JCustosTestExtension implements BeforeEachCallback, AfterEachCallback {

  private static final ExtensionContext.Namespace NS =
      ExtensionContext.Namespace.create(JCustosTestExtension.class);

  /** Creates the extension. */
  public JCustosTestExtension() {
  }

  @Override
  public void beforeEach(ExtensionContext context) {
    JCustosServiceResolver.resetAll();
    if (context == null) {
      return;
    }
    WithJCustosSubject annotation = findAnnotation(context);
    if (annotation != null) {
      JCustosTestFixture.Builder builder = JCustosTestFixture.builder()
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
      JCustosTestFixture fixture = builder.build();
      context.getStore(NS).put(JCustosTestFixture.class, fixture);
    }
  }

  @Override
  public void afterEach(ExtensionContext context) {
    if (context != null) {
      JCustosTestFixture fixture = context.getStore(NS)
          .remove(JCustosTestFixture.class, JCustosTestFixture.class);
      if (fixture != null) {
        fixture.close();
      }
    }
    JCustosServiceResolver.resetAll();
  }

  private static WithJCustosSubject findAnnotation(ExtensionContext context) {
    return context.getElement()
        .map(JCustosTestExtension::readAnnotation)
        .filter(a -> a != null)
        .orElseGet(() -> context.getTestClass()
            .map(JCustosTestExtension::readAnnotation)
            .orElse(null));
  }

  private static WithJCustosSubject readAnnotation(AnnotatedElement element) {
    return element.getAnnotation(WithJCustosSubject.class);
  }
}
