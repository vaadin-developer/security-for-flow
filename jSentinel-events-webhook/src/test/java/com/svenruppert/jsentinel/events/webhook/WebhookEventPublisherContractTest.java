package com.svenruppert.jsentinel.events.webhook;

/*-
 * #%L
 * jSentinel Events — Webhook exporter
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
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

import com.sun.net.httpserver.HttpServer;
import com.svenruppert.jsentinel.events.publisher.SignedEnvelopePublisher;
import com.svenruppert.jsentinel.events.testkit.EnvelopePublisherContract;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.net.InetSocketAddress;
import java.net.URI;

/**
 * Runs the shared {@link EnvelopePublisherContract} against a
 * {@link WebhookEventPublisher} targeting a real local always-200 endpoint.
 */
class WebhookEventPublisherContractTest implements EnvelopePublisherContract {

  private HttpServer server;
  private WebhookEventPublisher publisher;

  @BeforeEach
  void start() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/hook", exchange -> {
      exchange.getRequestBody().readAllBytes();
      exchange.sendResponseHeaders(200, -1);
      exchange.close();
    });
    server.start();
    publisher = new WebhookEventPublisher(WebhookPublisherConfig.defaults(
        URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/hook")));
  }

  @AfterEach
  void stop() {
    publisher.close();
    server.stop(0);
  }

  @Override
  public SignedEnvelopePublisher publisherUnderTest() {
    return publisher;
  }
}
