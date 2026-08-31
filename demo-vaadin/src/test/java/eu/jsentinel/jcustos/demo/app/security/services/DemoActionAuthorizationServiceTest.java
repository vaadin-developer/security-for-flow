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
package eu.jsentinel.jcustos.demo.app.security.services;

import eu.jsentinel.jcustos.action.ActionPermission;
import eu.jsentinel.jcustos.authorization.api.AccessDeniedException;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.permissions.DemoPermission;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the demo's {@link DemoActionAuthorizationService} against the
 * SPI-resolved {@link eu.jsentinel.jcustos.demo.app.security.services.MyAuthorizationService}.
 * The combination is what is actually wired in the demo at runtime; the
 * test pins the role → permission mapping so future regressions surface
 * here too.
 */
@DisplayName("DemoActionAuthorizationService — delegates through MyAuthorizationService")
class DemoActionAuthorizationServiceTest {

  private final DemoActionAuthorizationService service = new DemoActionAuthorizationService();
  private final RecordingAuditSink audit = new RecordingAuditSink();

  @BeforeEach
  void wire() {
    JSentinelServiceResolver.resetAll();
    JSentinelServiceResolver.setJSentinelAuditService(audit);
  }

  @AfterEach
  void reset() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  @DisplayName("isAllowed true for the permission the role carries")
  void isAllowedTrueForGrantedPermission() {
    MyUser admin = new MyUser(1L, "Admin",
        EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER));

    assertTrue(service.isAllowed(admin, DemoPermission.DEMO_ADMIN.actionPermission()));
    assertTrue(service.isAllowed(admin, DemoPermission.DEMO_EDIT.actionPermission()));
    assertTrue(service.isAllowed(admin, DemoPermission.DEMO_VIEW.actionPermission()));
  }

  @Test
  @DisplayName("isAllowed false for a permission the role does not carry")
  void isAllowedFalseForMissingPermission() {
    MyUser user = new MyUser(2L, "Plain", EnumSet.of(AuthorizationRole.USER));

    assertTrue(service.isAllowed(user, DemoPermission.DEMO_VIEW.actionPermission()));
    assertFalse(service.isAllowed(user, DemoPermission.DEMO_EDIT.actionPermission()));
    assertFalse(service.isAllowed(user, DemoPermission.DEMO_ADMIN.actionPermission()));
  }

  @Test
  @DisplayName("isAllowed false on null subject (delegate handles the null branch)")
  void isAllowedNullSubject() {
    assertFalse(service.isAllowed(null, DemoPermission.DEMO_VIEW.actionPermission()));
  }

  @Test
  @DisplayName("isAllowed false on null permission")
  void isAllowedNullPermission() {
    MyUser admin = new MyUser(1L, "Admin", EnumSet.of(AuthorizationRole.ADMIN));
    assertFalse(service.isAllowed(admin, null));
  }

  @Test
  @DisplayName("requireAllowed is a no-op for granted permissions")
  void requireAllowedSucceeds() {
    MyUser admin = new MyUser(1L, "Admin",
        EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER));

    service.requireAllowed(admin, DemoPermission.DEMO_ADMIN.actionPermission());

    assertEquals(0, audit.events().size(),
        "successful requireAllowed must not emit an audit event");
  }

  @Test
  @DisplayName("requireAllowed throws AccessDeniedException + emits ActionDenied")
  void requireAllowedDeniedEmitsAudit() {
    MyUser user = new MyUser(2L, "Plain", EnumSet.of(AuthorizationRole.USER));
    ActionPermission permission = DemoPermission.DEMO_ADMIN.actionPermission();

    assertThrows(AccessDeniedException.class,
        () -> service.requireAllowed(user, permission));

    assertEquals(1, audit.events().size(),
        "denied requireAllowed must publish exactly one ActionDenied event");
    assertEquals("eu.jsentinel.jcustos.audit.ActionDenied",
        audit.events().get(0).getClass().getName());
  }

}
