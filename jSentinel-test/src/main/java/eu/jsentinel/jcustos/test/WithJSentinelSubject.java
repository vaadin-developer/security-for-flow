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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Test annotation that binds a {@code JSentinelSubject} with the
 * declared roles and permissions for the duration of a JUnit-5 test
 * method (or every test method of an annotated class).
 *
 * <p>Activated by {@link JSentinelTestExtension}; combine via
 * {@code @ExtendWith(JSentinelTestExtension.class)} on the test
 * class.
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
 *
 * <p>Class-level annotation applies the same subject to every
 * {@code @Test} method in the class; a method-level annotation
 * overrides the class-level one.
 *
 * @since 00.74.00
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface WithJSentinelSubject {

  /** Subject id; defaults to {@code "test-subject"}. */
  String value() default "test-subject";

  /** Display name; defaults to {@link #value()}. */
  String displayName() default "";

  /** Role names to assign (e.g. {@code "ROLE_ADMIN"}). Order preserved. */
  String[] roles() default {};

  /** Permission names to assign (e.g. {@code "doc:read"}). Order preserved. */
  String[] permissions() default {};
}
