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
package eu.jsentinel.jcustos.demo.restclient.security;

import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
import eu.jsentinel.jcustos.authorization.api.permissions.HasPermissions;
import eu.jsentinel.jcustos.authorization.api.roles.HasRoles;
import eu.jsentinel.jcustos.demo.restclient.backend.RemoteUser;

import java.util.Objects;

/**
 * Authorization data is delivered by the backend at login time and stored
 * on the {@link RemoteUser} snapshot. This service simply returns the
 * snapshot — no further round-trips per UI decision.
 */
@JCustosAutoService(AuthorizationService.class)
public class RestBackedAuthorizationService implements AuthorizationService<RemoteUser> {

  @Override
  public HasRoles rolesFor(RemoteUser subject) {
    Objects.requireNonNull(subject, "subject");
    return subject;
  }

  @Override
  public HasPermissions permissionsFor(RemoteUser subject) {
    Objects.requireNonNull(subject, "subject");
    return subject;
  }
}
