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

import com.svenruppert.vaadin.security.authorization.api.AccessEvaluator;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.vaadin.flow.router.Location;

import java.lang.annotation.Annotation;
import java.util.Set;

public interface RoleBasedAccessEvaluatorAPI<T extends Annotation, U>
        extends AccessEvaluator<T> {


    /**
     * Resolves the {@link AuthorizationService} via SPI using {@link SecurityServiceResolver}.
     * <p>
     * If you need to deal with another technology, override this method in your implementation.
     * The resolved service is cached by the resolver.
     *
     * @return the AuthorizationService of your choice.
     */
    default AuthorizationService<U> authorizationService() {
        return SecurityServiceResolver.authorizationService();
    }


    /**
     * Mapping from a custom type to a defined type inside the generic implementation.
     * The Mapping could include dynamic parts, based on situation/date/time and so on.
     * For example, the Admin Role could be expanded to a set of custom specific
     * Admin Role Names.
     *
     * @param annotation the project specific annotation with the static content, something like UserRole.USER
     * @return a set of RoleName´s that are required by this annotation.
     */
    Set<RoleName> requiredRoles(T annotation);


    /**
     * based on the situation a alternative navigation target could be
     * defined. This method will be called if the the original navigation target could not
     * be ued based on missing Roles/Permissions of the active user.
     *
     * @param location         actual position on the side
     * @param navigationTarget where to go next
     * @param annotation       the annotation that holds the info
     * @return granted Access or a restricted one with an alternative navigation target
     */
    String alternativeNavigationTarget(Location location, Class<?> navigationTarget, T annotation);

}
