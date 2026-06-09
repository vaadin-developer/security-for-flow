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
package com.svenruppert.jsentinel.demo.app;

import com.svenruppert.jsentinel.demo.app.security.model.MyUser;
import com.svenruppert.jsentinel.demo.app.security.roles.AuthorizationRole;
import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.SubjectStores;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;

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
        JSentinelServiceResolver.authorizationService();
    return currentSubject.isPresent() && authorizationService.rolesFor(currentSubject.get())
                                                            .roleNames()
                                                            .stream()
                                                            .map(RoleName::roleName)
                                                            .anyMatch(subjectRole -> roles.contains(
                                                                AuthorizationRole.valueOf(subjectRole)));
  }
}
