package org.rapidpm.vaadin.security.authorization.api.roles;

import com.vaadin.flow.router.Location;
import org.rapidpm.vaadin.security.authorization.api.AccessEvaluator;
import org.rapidpm.vaadin.security.authorization.api.AuthorizationService;
import org.rapidpm.vaadin.security.authorization.api.AuthorizationServiceProvider;

import java.lang.annotation.Annotation;
import java.util.Set;

public interface RoleBasedAccessEvaluatorAPI<T extends Annotation, U>
        extends AccessEvaluator<T> {


    /**
     * This will call the ServiceLocator to get the Service.
     * If you need to deal with another technology, override this method in your implementation.
     * The default implementation is NOT caching!
     *
     * @return the AuthorizationService of your choice.
     */
    default AuthorizationService<U> authorizationService() {
        return (AuthorizationService<U>) new AuthorizationServiceProvider().load().get();
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
