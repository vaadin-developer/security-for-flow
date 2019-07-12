package org.rapidpm.vaadin.security.authorization.impl;

import org.rapidpm.frp.model.Pair;
import org.rapidpm.vaadin.security.authorization.api.AccessEvaluator;

import java.lang.annotation.Annotation;

public class AnnotationAccessEvaluatorPair<T extends Annotation>
    extends Pair<T, Class<? extends AccessEvaluator<T>>> {

  public AnnotationAccessEvaluatorPair(T t, Class<? extends AccessEvaluator<T>> aClass) {
    super(t, aClass);
  }

  public T annotation() {
    return getT1();
  }

  public Class<? extends AccessEvaluator<T>> accessEvaluatorClass() {
    return getT2();
  }
}
