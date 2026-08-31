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

import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;

import java.lang.annotation.Annotation;
import java.util.Set;

/**
 * Contract for role-based access evaluators.
 *
 * @param <T> the restriction annotation type
 * @param <U> the user/subject type
 */
public interface RoleBasedAccessEvaluatorAPI<T extends Annotation, U>
        extends AccessEvaluator<T> {

    /**
     * Resolves the {@link AuthorizationService} via SPI using {@link JSentinelServiceResolver}.
     * <p>
     * If you need to deal with another technology, override this method in your implementation.
     * The resolved service is cached by the resolver.
     *
     * @return the AuthorizationService of your choice.
     */
    default AuthorizationService<U> authorizationService() {
        return JSentinelServiceResolver.authorizationService();
    }

    /**
     * Mapping from a custom annotation to the set of role names required
     * for access. The mapping may include dynamic parts based on
     * situation, date/time, etc.
     *
     * @param annotation the restriction annotation instance
     * @return the set of required role names
     */
    Set<RoleName> requiredRoles(T annotation);

    /**
     * Determines the alternative navigation target when the subject
     * lacks the required roles.
     *
     * @param context          current access context
     * @param annotation       the restriction annotation
     * @return route string for the alternative target
     */
    String alternativeNavigationTarget(AccessContext context, T annotation);
}
