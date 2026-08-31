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
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class RequiresRoleEvaluatorWithHierarchyTest {

  private static final RoleName ADMIN = new RoleName("ROLE_ADMIN");
  private static final RoleName EDITOR = new RoleName("ROLE_EDITOR");
  private static final RoleName VIEWER = new RoleName("ROLE_VIEWER");

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
  }

  private static AccessContext ctxWith(Set<RoleName> heldRoles) {
    JCustosSubject subject = new JCustosSubject(
        "u-1", "u-1", heldRoles, Set.of());
    return new AccessContext(
        Optional.of(subject), "rest-endpoint", "/x", "read", Map.of());
  }

  private static RequiresRole annotationFor(String... values) {
    return new RequiresRole() {
      @Override public Class<? extends Annotation> annotationType() { return RequiresRole.class; }
      @Override public String[] value() { return values; }
    };
  }

  @Test
  @DisplayName("without hierarchy: held EDITOR is forbidden when ADMIN is required")
  void noHierarchyDirectMembership() {
    AuthorizationDecision decision = new RequiresRoleEvaluator()
        .evaluate(ctxWith(Set.of(EDITOR)), annotationFor("ROLE_ADMIN"));
    assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
  }

  @Test
  @DisplayName("with hierarchy: held ADMIN is granted when VIEWER is required (ADMIN -> EDITOR -> VIEWER)")
  void withHierarchyTransitiveGrant() {
    JCustosServiceResolver.setRoleHierarchy(StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(EDITOR)
        .role(EDITOR).inheritsFrom(VIEWER)
        .build());

    AuthorizationDecision decision = new RequiresRoleEvaluator()
        .evaluate(ctxWith(Set.of(ADMIN)), annotationFor("ROLE_VIEWER"));
    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
  }

  @Test
  @DisplayName("with hierarchy: held VIEWER is still forbidden when ADMIN is required (top-down only)")
  void withHierarchyDoesNotGoBottomUp() {
    JCustosServiceResolver.setRoleHierarchy(StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(EDITOR)
        .build());

    AuthorizationDecision decision = new RequiresRoleEvaluator()
        .evaluate(ctxWith(Set.of(VIEWER)), annotationFor("ROLE_ADMIN"));
    assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
  }

  @Test
  @DisplayName("with hierarchy: held EDITOR is granted when EDITOR is required (direct)")
  void withHierarchyDirectMatch() {
    JCustosServiceResolver.setRoleHierarchy(StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(EDITOR)
        .build());

    AuthorizationDecision decision = new RequiresRoleEvaluator()
        .evaluate(ctxWith(Set.of(EDITOR)), annotationFor("ROLE_EDITOR"));
    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
  }
}
