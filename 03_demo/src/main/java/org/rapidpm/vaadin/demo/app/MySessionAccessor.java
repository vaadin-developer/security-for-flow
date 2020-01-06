/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.rapidpm.vaadin.demo.app;

import org.rapidpm.vaadin.demo.app.security.model.MyUser;
import org.rapidpm.vaadin.demo.app.security.roles.AuthorizationRole;
import org.rapidpm.frp.model.Result;
import org.rapidpm.vaadin.security.authorization.api.*;
import org.rapidpm.vaadin.security.authorization.api.roles.RoleName;

import java.util.List;

import static java.util.Arrays.asList;

public interface MySessionAccessor
    extends SessionAccessor {


  static boolean isCurrentUserAuthorizedFor(AuthorizationRole... authorizationRoles) {
    if (authorizationRoles == null) return true;
    if (authorizationRoles.length == 0) return true;
    final List<AuthorizationRole>      roles                = asList(authorizationRoles);
    final Result<MyUser>               currentSubject       = SessionAccessor.currentSubject();
    final AuthorizationService<MyUser> authorizationService = new AuthorizationServiceProvider<MyUser>().load();
    return (currentSubject.isPresent()) && authorizationService.rolesFor(currentSubject.get())
                                                               .roleNames()
                                                               .map(RoleName::roleName)
                                                               .anyMatch(subjectRole -> roles.contains(
                                                                   AuthorizationRole.valueOf(subjectRole)));
  }


}
