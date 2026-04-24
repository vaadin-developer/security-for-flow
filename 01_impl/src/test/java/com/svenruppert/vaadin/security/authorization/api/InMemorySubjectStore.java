package com.svenruppert.vaadin.security.authorization.api;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link SubjectStore} for unit testing.
 * No Vaadin dependencies required.
 */
public class InMemorySubjectStore implements SubjectStore {

  private final Map<Class<?>, Object> store = new ConcurrentHashMap<>();

  @Override
  @SuppressWarnings("unchecked")
  public <T> Optional<T> currentSubject(Class<T> subjectType) {
    return Optional.ofNullable((T) store.get(subjectType));
  }

  @Override
  public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
    store.put(subjectType, subject);
  }

  @Override
  public <T> void deleteCurrentSubject(Class<T> subjectType) {
    store.remove(subjectType);
  }

  public void clear() {
    store.clear();
  }
}
