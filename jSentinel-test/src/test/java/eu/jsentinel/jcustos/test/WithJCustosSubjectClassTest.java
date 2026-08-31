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

import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Class-level {@link WithJCustosSubject} binds the same subject for
 * every test method in the class; a method-level annotation overrides
 * it.
 */
@ExtendWith(JCustosTestExtension.class)
@WithJCustosSubject(value = "class-default", roles = "ROLE_CLASS")
class WithJCustosSubjectClassTest {

  @Test
  @DisplayName("test inherits class-level annotation")
  void classAnnotationBindsSubject() {
    JCustosSubject bound = SubjectStores.subjectStore()
        .currentSubject(JCustosSubject.class)
        .orElseThrow();
    assertEquals("class-default", bound.subjectId());
    assertTrue(bound.roles().contains(new RoleName("ROLE_CLASS")));
  }

  @Test
  @WithJCustosSubject(value = "method-override", permissions = "p:override")
  @DisplayName("method-level annotation wins over class-level")
  void methodOverridesClass() {
    JCustosSubject bound = SubjectStores.subjectStore()
        .currentSubject(JCustosSubject.class)
        .orElseThrow();
    assertEquals("method-override", bound.subjectId());
    assertTrue(bound.permissions().contains(new PermissionName("p:override")));
  }
}
