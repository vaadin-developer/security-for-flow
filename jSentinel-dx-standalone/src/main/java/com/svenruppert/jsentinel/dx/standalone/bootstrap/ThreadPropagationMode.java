/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
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
package com.svenruppert.jsentinel.dx.standalone.bootstrap;

/**
 * Declares how the current {@code SubjectStore} subject should
 * (or should not) propagate into background / worker threads.
 *
 * <ul>
 *   <li>{@link #NONE} — the V00.70 default: per-thread,
 *       <strong>not</strong> inherited. Background work is the
 *       caller's responsibility.</li>
 *   <li>{@link #INHERIT_ON_SUBMIT} — when the consumer wraps an
 *       {@code Executor} via
 *       {@code StandaloneThreadPropagationContext.wrap(...)},
 *       submitted tasks run with the submitter's subject bound on
 *       the worker thread and the binding is cleared on return.</li>
 * </ul>
 *
 * @since 00.74.00
 */
public enum ThreadPropagationMode {

  /** Default — per-thread subject, no inheritance. */
  NONE,

  /** Wrap submitted Runnables to inherit the submitter's subject. */
  INHERIT_ON_SUBMIT
}
