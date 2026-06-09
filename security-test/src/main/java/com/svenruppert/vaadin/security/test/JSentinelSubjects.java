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
package com.svenruppert.vaadin.security.test;

import com.svenruppert.vaadin.security.authorization.api.JSentinelSubject;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Static factories for typical {@link JSentinelSubject} test fixtures.
 */
public final class JSentinelSubjects {

  private JSentinelSubjects() {
  }

  /**
   * Creates a subject with the given id, no roles, no permissions.
   *
   * @param subjectId non-blank id (also used as displayName)
   * @return subject
   */
  public static JSentinelSubject anonymousIdentity(String subjectId) {
    return new JSentinelSubject(subjectId, subjectId, Set.of(), Set.of());
  }

  /**
   * Creates a subject with the given id and a list of role names.
   *
   * @param subjectId non-blank id (also used as displayName)
   * @param roleNames role names
   * @return subject
   */
  public static JSentinelSubject withRoles(String subjectId, String... roleNames) {
    return new JSentinelSubject(subjectId, subjectId,
        Arrays.stream(roleNames).map(RoleName::new).collect(Collectors.toUnmodifiableSet()),
        Set.of());
  }

  /**
   * Creates a subject with the given id and a list of permission names.
   *
   * @param subjectId       non-blank id (also used as displayName)
   * @param permissionNames permission names
   * @return subject
   */
  public static JSentinelSubject withPermissions(String subjectId, String... permissionNames) {
    return new JSentinelSubject(subjectId, subjectId,
        Set.of(),
        Arrays.stream(permissionNames).map(PermissionName::new).collect(Collectors.toUnmodifiableSet()));
  }

  /**
   * Creates a subject with roles and permissions explicitly named.
   *
   * @param subjectId       non-blank id (also used as displayName)
   * @param roleNames       role names (may be empty)
   * @param permissionNames permission names (may be empty)
   * @return subject
   */
  public static JSentinelSubject of(
      String subjectId, Set<String> roleNames, Set<String> permissionNames) {
    return new JSentinelSubject(
        subjectId,
        subjectId,
        roleNames.stream().map(RoleName::new).collect(Collectors.toUnmodifiableSet()),
        permissionNames.stream().map(PermissionName::new).collect(Collectors.toUnmodifiableSet()));
  }
}
