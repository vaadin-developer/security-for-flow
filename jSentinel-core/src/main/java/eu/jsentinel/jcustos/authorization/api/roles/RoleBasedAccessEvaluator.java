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
package eu.jsentinel.jcustos.authorization.api.roles;

import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;

import java.lang.annotation.Annotation;
import java.util.Set;

/**
 * Base implementation for role-based access evaluation.
 * <p>
 * Returns an {@link AccessDecision} based on whether the current
 * subject has any of the required roles.
 *
 * @param <T> the restriction annotation type
 * @param <U> the user/subject type
 */
public abstract class RoleBasedAccessEvaluator<T extends Annotation, U>
        implements RoleBasedAccessEvaluatorAPI<T, U> {

    /** Creates a new instance. */
    protected RoleBasedAccessEvaluator() {
    }

    @Override
    public AccessDecision evaluate(AccessContext context, T annotation) {
        final Set<RoleName> roleNames = requiredRoles(annotation);

        // JS-SEC-011 (CWE-863): authenticate first. An empty required-role set
        // means "any authenticated subject", never "anyone" — so the subject
        // check must run before the empty-roles short-circuit, otherwise an
        // anonymous visitor is granted access to a @VisibleFor({}) route.
        final Class<U> subjectType = subjectType();
        final var currentSubject = SubjectStores.subjectStore().currentSubject(subjectType);
        if (currentSubject.isEmpty()) {
            return AccessDecision.denied(
                alternativeNavigationTarget(context, annotation), false);
        }

        if (roleNames.isEmpty()) {
            return AccessDecision.granted();
        }

        final AuthorizationService<U> authorizationService = this.authorizationService();
        final RoleHierarchy hierarchy = JSentinelServiceResolver.roleHierarchy();

        Set<RoleName> heldRoles = currentSubject.stream()
                .map(authorizationService::rolesFor)
                .flatMap(hr -> hr.roleNames().stream())
                .collect(java.util.stream.Collectors.toUnmodifiableSet());

        if (RoleMatcher.containsAnyImplied(heldRoles, roleNames, hierarchy)) {
            return AccessDecision.granted();
        }

        return AccessDecision.denied(
            alternativeNavigationTarget(context, annotation), true);
    }

    @SuppressWarnings("unchecked")
    private Class<U> subjectType() {
        return (Class<U>) JSentinelServiceResolver
            .<Object, Object>authenticationService()
            .subjectType();
    }
}
