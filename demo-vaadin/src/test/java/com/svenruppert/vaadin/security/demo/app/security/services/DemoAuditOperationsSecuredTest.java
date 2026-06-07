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
package com.svenruppert.vaadin.security.demo.app.security.services;

import com.svenruppert.proxybuilder.annotations.DelegatesTo;
import com.svenruppert.proxybuilder.annotations.GeneratedByProxyBuilder;
import com.svenruppert.vaadin.security.authorization.api.AccessDeniedException;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectStores;
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;
import com.svenruppert.vaadin.security.demo.app.security.roles.AuthorizationRole;
import com.svenruppert.vaadin.security.test.InMemorySubjectStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the V00.70 Phase-6 {@code security-processor} compile-time
 * path against the demo target {@link DemoAuditOperations}:
 * <ul>
 *   <li>The processor emits the {@code DemoAuditOperationsSecured}
 *       subclass alongside the source.</li>
 *   <li>The generated subclass enforces {@code @RequiresPermission}
 *       on {@code listEvents()} (single-perm) and
 *       {@code @RequiresAllPermissions} on
 *       {@code purgeAuditOlderThanDays(int)} (AND-semantics).</li>
 *   <li>Every guarded method carries the
 *       {@code @DelegatesTo} marker and the class itself carries
 *       {@code @GeneratedByProxyBuilder}.</li>
 * </ul>
 */
@DisplayName("DemoAuditOperationsSecured — V00.70 Phase-6 @Secured processor")
class DemoAuditOperationsSecuredTest {

  @BeforeEach
  void useInMemorySubjectStore() {
    // The demo's default SubjectStore is VaadinSessionSubjectStore which
    // requires an active Vaadin request thread — too heavy for a plain
    // junit test. Swap in the framework-supplied InMemorySubjectStore.
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
  }

  @AfterEach
  void tearDown() {
    SubjectStores.reset();
    SecurityServiceResolver.resetAll();
  }

  @Test
  @DisplayName("Generated subclass exists and is a DemoAuditOperations")
  void subclassExists() {
    DemoAuditOperationsSecured wrapper = new DemoAuditOperationsSecured();
    assertNotNull(wrapper);
    assertTrue(wrapper instanceof DemoAuditOperations,
        "generated class must be a DemoAuditOperations subclass");
  }

  @Test
  @DisplayName("Class carries @GeneratedByProxyBuilder, every guarded method carries @DelegatesTo")
  void generatedMarkersPresent() throws NoSuchMethodException {
    assertNotNull(
        DemoAuditOperationsSecured.class.getAnnotation(GeneratedByProxyBuilder.class),
        "@GeneratedByProxyBuilder must remain reflectable at runtime");

    Method list = DemoAuditOperationsSecured.class.getMethod("listEvents");
    DelegatesTo listDelegates = list.getAnnotation(DelegatesTo.class);
    assertNotNull(listDelegates, "listEvents must carry @DelegatesTo");
    assertTrue(listDelegates.value().contains("listEvents()"),
        "@DelegatesTo must reference the source method signature");

    Method purge = DemoAuditOperationsSecured.class
        .getMethod("purgeAuditOlderThanDays", int.class);
    DelegatesTo purgeDelegates = purge.getAnnotation(DelegatesTo.class);
    assertNotNull(purgeDelegates, "purgeAuditOlderThanDays must carry @DelegatesTo");
    assertTrue(purgeDelegates.value().contains("purgeAuditOlderThanDays(int)"));
  }

  @Test
  @DisplayName("listEvents throws AccessDeniedException without a subject")
  void listEventsDeniedWithoutSubject() {
    DemoAuditOperationsSecured wrapper = new DemoAuditOperationsSecured();
    assertThrows(AccessDeniedException.class, wrapper::listEvents,
        "no current subject → SecurityEnforcer must refuse audit:read");
  }

  @Test
  @DisplayName("listEvents succeeds when the current subject holds audit:read (ADMIN role)")
  void listEventsAllowedForAdmin() {
    bindAdmin();
    DemoAuditOperationsSecured wrapper = new DemoAuditOperationsSecured();
    assertNotNull(wrapper.listEvents(),
        "admin subject must clear the audit:read guard");
  }

  @Test
  @DisplayName("purgeAuditOlderThanDays denied when subject only has audit:read")
  void purgeDeniedForViewerLevelSubject() {
    // Bind a Q_ADMIN subject — has audit:read but NOT audit:purge per
    // MyAuthorizationService. The AND-semantics on purge must refuse.
    bindQAdmin();
    DemoAuditOperationsSecured wrapper = new DemoAuditOperationsSecured();
    assertThrows(AccessDeniedException.class,
        () -> wrapper.purgeAuditOlderThanDays(30),
        "Q_ADMIN lacks audit:purge → AND-semantics must refuse");
  }

  @Test
  @DisplayName("purgeAuditOlderThanDays allowed for ADMIN (has both audit:read + audit:purge)")
  void purgeAllowedForAdmin() {
    bindAdmin();
    DemoAuditOperationsSecured wrapper = new DemoAuditOperationsSecured();
    assertEquals(0, wrapper.purgeAuditOlderThanDays(30),
        "demo no-op purge returns the current audit count (0 in a fresh JVM)");
  }

  private static void bindAdmin() {
    SubjectStores.subjectStore().setCurrentSubject(
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)),
        MyUser.class);
  }

  private static void bindQAdmin() {
    SubjectStores.subjectStore().setCurrentSubject(
        new MyUser(2L, "Quasi-Admin",
            EnumSet.of(AuthorizationRole.Q_ADMIN, AuthorizationRole.USER)),
        MyUser.class);
  }
}
