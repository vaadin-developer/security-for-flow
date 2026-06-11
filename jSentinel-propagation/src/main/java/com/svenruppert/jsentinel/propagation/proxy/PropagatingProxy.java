/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.jsentinel.propagation.proxy;

import com.svenruppert.jsentinel.annotations.PropagateToken;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.credential.propagation.HeaderValue;
import com.svenruppert.jsentinel.credential.propagation.OutboundCall;
import com.svenruppert.jsentinel.credential.propagation.OutboundHeaderContext;
import com.svenruppert.jsentinel.credential.propagation.PropagateTokenAdvisor;
import com.svenruppert.jsentinel.credential.propagation.TokenCredentialStore;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Runtime / JDK Dynamic Proxy path for {@code @PropagateToken}.
 *
 * <p>{@code PropagatingProxy.wrap(Interface.class, impl)} returns a
 * proxy that, on every annotated method call, binds the advisor-resolved
 * {@link HeaderValue} into {@link OutboundHeaderContext} for the
 * duration of the delegate call and clears in {@code finally}. Useful
 * for tests, lambdas, and consumers that already work with interfaces;
 * production code on concrete classes uses the compile-time
 * {@code <Type>Propagating} wrapper (V00.74 Prompt 013).
 *
 * <p>{@code Object.toString()}, {@code equals()}, {@code hashCode()}
 * on the proxy short-circuit to delegate-only — they are never
 * annotated.
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public final class PropagatingProxy {

  private PropagatingProxy() {
    throw new AssertionError("no instances");
  }

  /**
   * Wrap {@code delegate} behind a JDK Dynamic Proxy that runs the
   * {@link PropagateTokenAdvisor.Default} for every
   * {@code @PropagateToken}-annotated call.
   *
   * @param contract the interface — must be an interface type
   * @param delegate the underlying implementation
   * @param <T>      the contract type
   * @return a propagation-aware proxy
   * @throws IllegalArgumentException if {@code contract} is not an interface
   */
  @SuppressWarnings("unchecked")
  public static <T> T wrap(Class<T> contract, T delegate) {
    Objects.requireNonNull(contract, "contract");
    Objects.requireNonNull(delegate, "delegate");
    if (!contract.isInterface()) {
      throw new IllegalArgumentException(
          "PropagatingProxy.wrap requires an interface; got " + contract.getName());
    }
    return (T) Proxy.newProxyInstance(
        contract.getClassLoader(),
        new Class<?>[]{contract},
        new Handler<>(contract, delegate));
  }

  /**
   * Invocation handler — looks up {@code @PropagateToken} per method,
   * runs the advisor, binds {@link OutboundHeaderContext}, delegates,
   * clears.
   */
  private static final class Handler<T> implements InvocationHandler {

    private final Class<T> contract;
    private final T delegate;

    Handler(Class<T> contract, T delegate) {
      this.contract = contract;
      this.delegate = delegate;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      if (method.getDeclaringClass() == Object.class) {
        return invokeDirect(method, args);
      }
      PropagateToken annotation = findAnnotation(method);
      if (annotation == null) {
        return invokeDirect(method, args);
      }
      TokenCredentialStore store = JSentinelServiceResolver.tokenCredentialStore();
      OutboundCall call = new OutboundCall(
          contract.getSimpleName(),
          method.getName(),
          annotation.audience(),
          Map.of());
      Optional<HeaderValue> header = PropagateTokenAdvisor.Default.INSTANCE
          .adviseFor(annotation, call, store);
      if (header.isEmpty()) {
        return invokeDirect(method, args);
      }
      OutboundHeaderContext.bind(header.get());
      try {
        return invokeDirect(method, args);
      } finally {
        OutboundHeaderContext.clear();
      }
    }

    /**
     * Method-level annotation if present, otherwise class-level.
     * Identical resolution rule to {@code @RequiresRole}.
     */
    private PropagateToken findAnnotation(Method method) {
      PropagateToken methodLevel = method.getAnnotation(PropagateToken.class);
      if (methodLevel != null) return methodLevel;
      return contract.getAnnotation(PropagateToken.class);
    }

    private Object invokeDirect(Method method, Object[] args) throws Throwable {
      try {
        return method.invoke(delegate, args);
      } catch (InvocationTargetException e) {
        throw e.getCause();
      }
    }
  }
}
