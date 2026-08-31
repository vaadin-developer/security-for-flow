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
package eu.jsentinel.jcustos.demo.app.security.roles;

import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.views.MainView;
import eu.jsentinel.jcustos.demo.app.views.MyLoginView;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("MyRoleAccessEvaluator — VisibleFor decision matrix")
class MyRoleAccessEvaluatorTest {

  private final MyRoleAccessEvaluator evaluator = new MyRoleAccessEvaluator();
  private final InMemorySubjectStore store = new InMemorySubjectStore();

  @BeforeEach
  void installSubjectStore() {
    SubjectStores.setSubjectStore(store);
  }

  @AfterEach
  void resetSubjectStore() {
    store.clear();
    SubjectStores.reset();
  }

  @Test
  @DisplayName("Empty @VisibleFor (no roles required) grants access")
  void emptyAnnotationGrants() {
    AccessDecision decision = evaluator.evaluate(ctx(),
        new VisibleForLiteral());

    assertInstanceOf(AccessDecision.Granted.class, decision);
  }

  @Test
  @DisplayName("No current subject reroutes to the login view (non-forward)")
  void anonymousReroutesToLogin() {
    // store is empty
    AccessDecision decision = evaluator.evaluate(ctx(),
        new VisibleForLiteral(AuthorizationRole.USER));

    AccessDecision.Reroute reroute = assertInstanceOf(AccessDecision.Reroute.class, decision);
    assertEquals(MyLoginView.NAV, reroute.target(),
        "anonymous access must reroute to MyLoginView");
    assertFalse(reroute.asForward(),
        "anonymous reroute must not be a forward");
  }

  @Test
  @DisplayName("Subject with the required role is granted access")
  void matchingRoleGrants() {
    store.setCurrentSubject(
        new MyUser(1L, "Alice", EnumSet.of(AuthorizationRole.USER, AuthorizationRole.ADMIN)),
        MyUser.class);

    AccessDecision decision = evaluator.evaluate(ctx(),
        new VisibleForLiteral(AuthorizationRole.ADMIN));

    assertInstanceOf(AccessDecision.Granted.class, decision);
  }

  @Test
  @DisplayName("Subject without any of the required roles is rerouted to MainView (forward)")
  void wrongRoleForwardsToMainView() {
    store.setCurrentSubject(
        new MyUser(2L, "Bob", EnumSet.of(AuthorizationRole.USER)),
        MyUser.class);

    AccessDecision decision = evaluator.evaluate(ctx(),
        new VisibleForLiteral(AuthorizationRole.ADMIN));

    AccessDecision.Reroute reroute = assertInstanceOf(AccessDecision.Reroute.class, decision);
    assertEquals(MainView.NAV, reroute.target(),
        "unauthorised access must reroute to MainView");
    assertTrue(reroute.asForward(),
        "unauthorised reroute must be a forward (preserve URL)");
  }

  @Test
  @DisplayName("Any one matching role out of several is enough")
  void firstMatchWins() {
    store.setCurrentSubject(
        new MyUser(3L, "Carol", EnumSet.of(AuthorizationRole.NERD)),
        MyUser.class);

    AccessDecision decision = evaluator.evaluate(ctx(),
        new VisibleForLiteral(AuthorizationRole.ADMIN, AuthorizationRole.NERD));

    assertInstanceOf(AccessDecision.Granted.class, decision);
  }

  // ── Fixtures ──────────────────────────────────────────────────

  private static AccessContext ctx() {
    return new AccessContext("/test", MyRoleAccessEvaluatorTest.class, Map.of());
  }

  private record VisibleForLiteral(AuthorizationRole... roles) implements VisibleFor {
    @Override public AuthorizationRole[] value() { return roles; }
    @Override public Class<? extends java.lang.annotation.Annotation> annotationType() { return VisibleFor.class; }
  }

  private static final class InMemorySubjectStore implements SubjectStore {
    private final Map<Class<?>, Object> store = new HashMap<>();

    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) {
      return Optional.ofNullable(subjectType.cast(store.get(subjectType)));
    }

    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
      store.put(subjectType, subject);
    }

    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) {
      store.remove(subjectType);
    }

    void clear() {
      store.clear();
    }
  }
}
