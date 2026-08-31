package eu.jsentinel.jcustos.demo.skill.vaadin.security.roles;

import eu.jsentinel.jcustos.authorization.annotations.JCustosAnnotation;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Restriction annotation. Applied to a Vaadin route view
 * ({@code @VisibleFor(ADMIN)}), it is picked up by
 * {@code JCustosAnnotationScanner} and evaluated by
 * {@link RoleAccessEvaluator} during {@code BeforeEnter}.
 *
 * <p>{@code value()} is any-of: at least one of the listed roles must
 * be present on the subject for navigation to proceed.
 */
@Retention(RetentionPolicy.RUNTIME)
@JCustosAnnotation(RoleAccessEvaluator.class)
public @interface VisibleFor {
  AuthorizationRole[] value();
}
