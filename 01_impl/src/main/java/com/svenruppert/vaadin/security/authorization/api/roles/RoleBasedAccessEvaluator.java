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
package com.svenruppert.vaadin.security.authorization.api.roles;

import com.svenruppert.functional.model.Result;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.SessionAccessor;
import com.svenruppert.vaadin.security.authorization.navigation.AuthorizationDecision;
import com.vaadin.flow.router.Location;

import java.lang.annotation.Annotation;
import java.util.Set;

/**
 * Base implementation for role-based access evaluation.
 * <p>
 * Returns an {@link AuthorizationDecision} based on whether the current
 * subject has any of the required roles.
 *
 * @param <T> the restriction annotation type
 * @param <U> the user/subject type
 */
public abstract class RoleBasedAccessEvaluator<T extends Annotation, U>
        implements RoleBasedAccessEvaluatorAPI<T, U> {

    @Override
    public AuthorizationDecision evaluateAccess(Location location, Class<?> navigationTarget, T annotation) {
        final Set<RoleName> roleNames = requiredRoles(annotation);

        if (roleNames.isEmpty()) {
            return AuthorizationDecision.granted();
        }

        final Result<U> currentSubject = SessionAccessor.currentSubject();
        if (currentSubject.isAbsent()) {
            return AuthorizationDecision.denied(
                alternativeNavigationTarget(location, navigationTarget, annotation), false);
        }

        final AuthorizationService<U> authorizationService = this.authorizationService();

        boolean hasRole = currentSubject.stream()
                .map(authorizationService::rolesFor)
                .flatMap(hr -> hr.roleNames().stream())
                .anyMatch(roleNames::contains);

        if (hasRole) {
            return AuthorizationDecision.granted();
        }

        return AuthorizationDecision.denied(
            alternativeNavigationTarget(location, navigationTarget, annotation), true);
    }
}
