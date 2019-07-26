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
package demo.app.security.services;

import demo.app.security.model.MyUser;
import org.rapidpm.vaadin.security.authorization.api.AuthorizationService;
import org.rapidpm.vaadin.security.authorization.api.permissions.HasPermissions;
import org.rapidpm.vaadin.security.authorization.api.roles.HasRoles;
import org.rapidpm.vaadin.security.authorization.api.roles.RoleName;

import java.util.Objects;
import java.util.stream.Stream;

public class MyAuthorizationService
    implements AuthorizationService<MyUser> {

  @Override
  public HasRoles rolesFor(MyUser subject) {
    Objects.requireNonNull(subject);
    return () -> subject.roles()
                        .stream()
                        .map(Enum::name)
                        .map(RoleName::new);
  }

  @Override
  public HasPermissions permissionsFor(MyUser subject) {
    Objects.requireNonNull(subject);
    return Stream::empty;
  }
}
