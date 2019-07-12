package org.rapidpm.vaadin.security.authorization.api;

public interface AuthenticationService<T, U> {

  boolean checkCredentials(T credentials);

  U loadSubject(T credentials);

  Class<U> subjectType();

}
