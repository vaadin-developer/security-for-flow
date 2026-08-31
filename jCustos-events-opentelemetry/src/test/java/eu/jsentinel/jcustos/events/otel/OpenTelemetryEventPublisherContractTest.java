package eu.jsentinel.jcustos.events.otel;

/*-
 * #%L
 * jCustos Events — OpenTelemetry exporter
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.events.publisher.SignedEnvelopePublisher;
import eu.jsentinel.jcustos.events.testkit.EnvelopePublisherContract;
import io.opentelemetry.api.logs.LoggerProvider;

/**
 * Runs the shared {@link EnvelopePublisherContract} against the publisher on
 * a noop {@link LoggerProvider} — the wiring recommended for applications
 * without a collector.
 */
class OpenTelemetryEventPublisherContractTest implements EnvelopePublisherContract {

  private final OpenTelemetryEventPublisher publisher =
      new OpenTelemetryEventPublisher(LoggerProvider.noop());

  @Override
  public SignedEnvelopePublisher publisherUnderTest() {
    return publisher;
  }
}
