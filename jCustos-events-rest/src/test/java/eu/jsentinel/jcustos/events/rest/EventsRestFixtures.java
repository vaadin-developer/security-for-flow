package eu.jsentinel.jcustos.events.rest;

/*-
 * #%L
 * jCustos Events — REST / SSE bridge
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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.bus.ConsumePipeline;
import eu.jsentinel.jcustos.events.bus.PublishPipeline;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.codec.RecordReflectionCanonicalizer;
import eu.jsentinel.jcustos.events.keys.InMemoryKeyManagement;
import eu.jsentinel.jcustos.events.producer.AllowListProducerPolicy;
import eu.jsentinel.jcustos.events.producer.JCustosEventProducerPolicy;
import eu.jsentinel.jcustos.events.replay.InMemoryReplayStore;
import eu.jsentinel.jcustos.events.sequence.InMemorySequenceStore;
import eu.jsentinel.jcustos.events.sequence.SequenceValidator;
import eu.jsentinel.jcustos.events.sequence.SequenceViolationStrategy;
import eu.jsentinel.jcustos.events.signature.Ed25519SignatureAlgorithm;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithms;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Duration;
import java.time.Instant;

/** Real signing/verification wiring for the events-rest tests — no mocks. */
final class EventsRestFixtures {

  static final Instant T0 = Instant.parse("2026-06-24T10:00:00Z");
  static final EventProducerId PRODUCER = EventProducerId.of("rest-service-primary");

  final InMemoryKeyManagement keyManagement =
      new InMemoryKeyManagement(new Ed25519SignatureAlgorithm(), KeyId.of("eventbus-1"));
  final JCustosEventProducerPolicy allowAll = AllowListProducerPolicy.builder()
      .allow(PRODUCER, LoginSucceededEvent.TYPE)
      .build();

  PublishPipeline newPublishPipeline() {
    return new PublishPipeline(keyManagement, new RecordReflectionCanonicalizer(),
        new CanonicalJsonPayloadCodec(), PayloadHashAlgorithm.SHA_256, PRODUCER,
        new InMemorySequenceStore(), new InMemoryReplayStore(), allowAll,
        Duration.ofMinutes(5), () -> T0);
  }

  ConsumePipeline newConsumePipeline() {
    return new ConsumePipeline(keyManagement, SignatureAlgorithms.defaults(),
        new InMemoryReplayStore(), new InMemorySequenceStore(), new SequenceValidator(),
        SequenceViolationStrategy.REJECT, allowAll);
  }

  SignedJCustosEventEnvelope signedEnvelope() {
    EventMetadata meta = EventMetadata.create(TenantId.DEFAULT, SubjectId.of("alice"),
        T0, JCustosEventSeverity.INFO);
    return newPublishPipeline().toEnvelope(new LoginSucceededEvent(meta, "password"));
  }
}
