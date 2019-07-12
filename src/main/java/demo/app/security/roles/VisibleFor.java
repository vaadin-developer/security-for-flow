package demo.app.security.roles;

import org.rapidpm.vaadin.security.authorization.annotations.NavigationAnnotation;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@NavigationAnnotation(MyRoleAccessEvaluator.class)
public @interface VisibleFor {
  AuthorizationRole[] value();
}
