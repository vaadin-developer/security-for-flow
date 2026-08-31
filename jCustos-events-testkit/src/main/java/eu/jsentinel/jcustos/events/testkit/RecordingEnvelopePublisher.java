package eu.jsentinel.jcustos.events.testkit;

/*-
 * #%L
 * jCustos Events — Contract testkit
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.publisher.SignedEnvelopePublisher;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Recording {@link SignedEnvelopePublisher} test double (no mock framework):
 * captures every delivered envelope, and can optionally be switched into a
 * failing mode to exercise the bus's publisher-failure isolation.
 *
 * <p>In failing mode each delivery is <em>recorded first, then thrown</em> —
 * a test can assert both that the bus attempted the delivery and that the
 * failure was isolated.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class RecordingEnvelopePublisher implements SignedEnvelopePublisher {

  private final List<SignedJCustosEventEnvelope> received = new CopyOnWriteArrayList<>();
  private volatile RuntimeException failure;

  @Override
  public void onEnvelope(SignedJCustosEventEnvelope envelope) {
    received.add(envelope);
    RuntimeException toThrow = failure;
    if (toThrow != null) {
      throw toThrow;
    }
  }

  /**
   * @return a defensive copy of every envelope delivered so far, in order
   */
  public List<SignedJCustosEventEnvelope> received() {
    return List.copyOf(received);
  }

  /**
   * Switches this publisher into failing mode: every subsequent delivery is
   * recorded and then throws {@code failure}.
   *
   * @param failure the exception to throw on each delivery
   * @return this publisher, for fluent test setup
   */
  public RecordingEnvelopePublisher failWith(RuntimeException failure) {
    this.failure = failure;
    return this;
  }
}
