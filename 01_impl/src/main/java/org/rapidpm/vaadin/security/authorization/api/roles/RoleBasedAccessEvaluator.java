/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.rapidpm.vaadin.security.authorization.api.roles;

import com.vaadin.flow.router.Location;
import org.rapidpm.frp.model.Result;
import org.rapidpm.vaadin.security.authorization.api.AuthorizationService;
import org.rapidpm.vaadin.security.authorization.api.SessionAccessor;
import org.rapidpm.vaadin.security.authorization.impl.Access;

import java.lang.annotation.Annotation;
import java.util.Set;

import static org.rapidpm.vaadin.security.authorization.impl.Access.granted;
import static org.rapidpm.vaadin.security.authorization.impl.Access.restricted;

/**
 * @param <T> Annotation on the View class , something like VisibleFor(..)
 * @param <U> The User - class
 */
public abstract class RoleBasedAccessEvaluator<T extends Annotation, U>
        implements RoleBasedAccessEvaluatorAPI<T, U> {

    @Override
    public Access evaluate(Location location, Class<?> navigationTarget, T annotation) {
        final Set<RoleName> roleNames = requiredRoles(annotation);

        if (roleNames.isEmpty()) return granted();

        final Result<U> currentSubject = SessionAccessor.currentSubject();
        if (currentSubject.isAbsent())
            return restricted(alternativeNavigationTarget(location, navigationTarget, annotation), false);

        final AuthorizationService<U> authorizationService = this.authorizationService();

        return currentSubject.stream()
                .map(authorizationService::rolesFor)
                .flatMap(HasRoles::roleNames)
                .filter(roleNames::contains)
                .findFirst()
                .map(rn -> granted())
                .orElse(restricted(alternativeNavigationTarget(location, navigationTarget, annotation), true));
    }
}
