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
package eu.jsentinel.jcustos.authorization.api.roles;

import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.JSentinelSubject;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

@DisplayName("RequiresRoleEvaluator")
class RequiresRoleEvaluatorTest {

  private final RequiresRoleEvaluator evaluator = new RequiresRoleEvaluator();

  @Test
  @DisplayName("missing subject is unauthenticated")
  void missingSubject() throws NoSuchMethodException {
    AuthorizationDecision decision = evaluator.evaluate(
        context(Optional.empty()),
        annotation());

    assertInstanceOf(AuthorizationDecision.Unauthenticated.class, decision);
  }

  @Test
  @DisplayName("matching role grants access")
  void matchingRole() throws NoSuchMethodException {
    JSentinelSubject subject = new JSentinelSubject(
        "u1", "User", Set.of(new RoleName("ROLE_ADMIN")), Set.of());

    AuthorizationDecision decision = evaluator.evaluate(
        context(Optional.of(subject)),
        annotation());

    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
  }

  @Test
  @DisplayName("missing role forbids access")
  void missingRole() throws NoSuchMethodException {
    JSentinelSubject subject = new JSentinelSubject(
        "u1", "User", Set.of(new RoleName("ROLE_VIEWER")), Set.of());

    AuthorizationDecision decision = evaluator.evaluate(
        context(Optional.of(subject)),
        annotation());

    assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
  }

  private static AccessContext context(Optional<JSentinelSubject> subject) {
    return new AccessContext(subject, "rest-endpoint", "/admin", "access", Map.of());
  }

  private static RequiresRole annotation() throws NoSuchMethodException {
    Method method = Fixtures.class.getDeclaredMethod("admin");
    return method.getAnnotation(RequiresRole.class);
  }

  static class Fixtures {
    @RequiresRole("ROLE_ADMIN")
    void admin() {
    }
  }
}
