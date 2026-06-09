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

import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.api.SubjectStores;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that {@link JSentinelTestExtension} reads
 * {@link WithJSentinelSubject} from a test method and binds the
 * subject before the body runs.
 */
@ExtendWith(JSentinelTestExtension.class)
class WithJSentinelSubjectMethodTest {

  @Test
  @WithJSentinelSubject(
      value = "alice",
      displayName = "Alice Admin",
      roles = {"ROLE_ADMIN", "ROLE_USER"},
      permissions = {"doc:read", "doc:delete"}
  )
  @DisplayName("method-level annotation binds the subject with declared identity")
  void methodAnnotationBindsSubject() {
    JSentinelSubject bound = SubjectStores.subjectStore()
        .currentSubject(JSentinelSubject.class)
        .orElseThrow();

    assertEquals("alice", bound.subjectId());
    assertEquals("Alice Admin", bound.displayName());
    assertTrue(bound.roles().contains(new RoleName("ROLE_ADMIN")));
    assertTrue(bound.roles().contains(new RoleName("ROLE_USER")));
    assertTrue(bound.permissions().contains(new PermissionName("doc:read")));
    assertTrue(bound.permissions().contains(new PermissionName("doc:delete")));
  }

  @Test
  @DisplayName("no annotation → no bound subject (only resolver reset)")
  void noAnnotationLeavesStoreUnbound() {
    assertFalse(SubjectStores.findSubjectStore()
        .flatMap(s -> s.currentSubject(JSentinelSubject.class))
        .isPresent());
  }
}
