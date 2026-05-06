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
package com.svenruppert.vaadin.security.demo.rest.server;

import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoRolePermissionMapping;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoUser;
import com.svenruppert.vaadin.security.rest.BearerTokenExtractor;
import com.svenruppert.vaadin.security.rest.RestRequest;
import com.svenruppert.vaadin.security.rest.RestSubjectResolver;

import java.util.Optional;
import java.util.Set;

/**
 * Demo {@link RestSubjectResolver} that resolves a {@code Bearer} token from
 * the {@code Authorization} header (parsed via {@link BearerTokenExtractor})
 * and looks it up in {@link DemoTokenStore}.
 */
public final class DemoSubjectResolver implements RestSubjectResolver {

  private static final BearerTokenExtractor BEARER = new BearerTokenExtractor();

  private final DemoTokenStore tokens;
  private final DemoRolePermissionMapping mapping;

  public DemoSubjectResolver(DemoTokenStore tokens, DemoRolePermissionMapping mapping) {
    this.tokens = tokens;
    this.mapping = mapping;
  }

  @Override
  public Optional<SecuritySubject> resolveSubject(RestRequest request) {
    return extractToken(request).flatMap(tokens::resolve).map(this::toSubject);
  }

  static Optional<String> extractToken(RestRequest request) {
    return BEARER.extract(request);
  }

  private SecuritySubject toSubject(DemoUser user) {
    RoleName roleName = user.role().roleName();
    Set<PermissionName> permissions = mapping.permissionsFor(roleName);
    return new SecuritySubject(
        user.username(),
        user.displayName(),
        Set.of(roleName),
        permissions);
  }
}
