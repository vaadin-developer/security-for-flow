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
package com.svenruppert.vaadin.security.demo.rest;

import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.rest.RestRequest;
import com.svenruppert.vaadin.security.rest.RestSubjectResolver;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Demo resolver that maps an {@code X-Demo-Role} header to a security subject.
 */
public final class DemoRestSubjectResolver implements RestSubjectResolver {

  private final DemoRolePermissionMapping mapping = new DemoRolePermissionMapping();

  @Override
  public Optional<SecuritySubject> resolveSubject(RestRequest request) {
    return Optional.ofNullable(request.headers().get("X-Demo-Role"))
        .map(DemoRole::valueOf)
        .map(this::subjectFor);
  }

  private SecuritySubject subjectFor(DemoRole role) {
    RoleName roleName = role.roleName();
    Set<PermissionName> permissions = mapping.permissionsFor(roleName);
    return new SecuritySubject(
        role.name().toLowerCase(),
        role.name(),
        Set.of(roleName),
        permissions.stream().collect(Collectors.toUnmodifiableSet()));
  }
}
