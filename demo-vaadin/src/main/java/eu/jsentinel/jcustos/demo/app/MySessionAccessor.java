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
package eu.jsentinel.jcustos.demo.app;

import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;

import java.util.List;
import java.util.Optional;

import static java.util.Arrays.asList;

public interface MySessionAccessor {

  static boolean isCurrentUserAuthorizedFor(AuthorizationRole... authorizationRoles) {
    if (authorizationRoles == null) return true;
    if (authorizationRoles.length == 0) return true;
    final List<AuthorizationRole> roles = asList(authorizationRoles);
    final Optional<MyUser> currentSubject = SubjectStores.subjectStore().currentSubject(MyUser.class);
    final AuthorizationService<MyUser> authorizationService =
        JCustosServiceResolver.authorizationService();
    return currentSubject.isPresent() && authorizationService.rolesFor(currentSubject.get())
                                                            .roleNames()
                                                            .stream()
                                                            .map(RoleName::roleName)
                                                            .anyMatch(subjectRole -> roles.contains(
                                                                AuthorizationRole.valueOf(subjectRole)));
  }
}
