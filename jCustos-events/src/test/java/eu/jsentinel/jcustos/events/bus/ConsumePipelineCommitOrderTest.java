package eu.jsentinel.jcustos.events.bus;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.codec.RecordReflectionCanonicalizer;
import eu.jsentinel.jcustos.events.replay.InMemoryReplayStore;
import eu.jsentinel.jcustos.events.sequence.InMemorySequenceStore;
import eu.jsentinel.jcustos.events.sequence.JCustosEventSequenceStore;
import eu.jsentinel.jcustos.events.sequence.SequenceValidator;
import eu.jsentinel.jcustos.events.sequence.SequenceViolationStrategy;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithms;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ConsumePipeline — commit order: sequence CAS before markSeen (R04)")
class ConsumePipelineCommitOrderTest {

  @Test
  @DisplayName("a sequence-rejected envelope is never marked seen; the accepted one is")
  void rejectedEnvelopeLeavesReplayStoreClean() {
    BusFixtures fx = new BusFixtures();
    // Two distinct, validly signed envelopes claiming the SAME sequence (1):
    // same signing key + producer, but separate publish-side sequence stores.
    SignedJCustosEventEnvelope a = fx.publishPipeline().toEnvelope(BusFixtures.event());
    PublishPipeline secondPublisher = new PublishPipeline(fx.keyManagement,
        new RecordReflectionCanonicalizer(), new CanonicalJsonPayloadCodec(),
        PayloadHashAlgorithm.SHA_256, BusFixtures.PRODUCER, new InMemorySequenceStore(),
        new InMemoryReplayStore(), fx.allowAll, Duration.ofMinutes(5), () -> BusFixtures.T0);
    SignedJCustosEventEnvelope b = secondPublisher.toEnvelope(BusFixtures.event());
    assertEquals(a.sequence(), b.sequence(), "premise: both envelopes claim the same sequence");

    ConsumePipeline consumer = fx.consumePipeline();
    assertTrue(consumer.verify(a, BusFixtures.T0).isValid());
    assertInstanceOf(JCustosEventVerificationResult.SequenceViolation.class,
        consumer.verify(b, BusFixtures.T0));

    assertTrue(fx.consumeReplay.hasSeen(a.envelopeId()),
        "the accepted envelope IS marked seen");
    assertFalse(fx.consumeReplay.hasSeen(b.envelopeId()),
        "a sequence-rejected envelope must NOT be marked seen — its later legitimate"
            + " reprocessing must not be misclassified as replay (R04)");
  }

  @Test
  @DisplayName("a CAS-losing envelope is rejected as SequenceViolation without a replay-store entry")
  void casLosingEnvelopeIsNotMarkedSeen() {
    BusFixtures fx = new BusFixtures();
    PublishPipeline publisher = fx.publishPipeline();
    SignedJCustosEventEnvelope a = publisher.toEnvelope(BusFixtures.event()); // sequence 1
    SignedJCustosEventEnvelope b = publisher.toEnvelope(BusFixtures.event()); // sequence 2

    RacingSequenceStore racing = new RacingSequenceStore();
    ConsumePipeline consumer = new ConsumePipeline(fx.keyManagement,
        SignatureAlgorithms.defaults(), fx.consumeReplay, racing, new SequenceValidator(),
        SequenceViolationStrategy.REJECT, fx.allowAll);

    assertTrue(consumer.verify(a, BusFixtures.T0).isValid()); // store advances to 1

    // B passes the read-only sequence gate against observed last=1, but a
    // competing consumer commits sequence 2 inside the read-to-CAS window —
    // exactly the race in which the old markSeen-first order poisoned the
    // replay store with the id of a rejected envelope.
    racing.raceOnNextRead();
    assertInstanceOf(JCustosEventVerificationResult.SequenceViolation.class,
        consumer.verify(b, BusFixtures.T0));
    assertFalse(fx.consumeReplay.hasSeen(b.envelopeId()),
        "a CAS-losing envelope must not poison the replay store (R04)");

    // Residual semantics: the redelivery of B is rejected via SequenceViolation
    // (its sequence was consumed by the competitor) — fail-closed, but NOT via
    // ReplayDetected, and the replay store stays clean.
    assertInstanceOf(JCustosEventVerificationResult.SequenceViolation.class,
        consumer.verify(b, BusFixtures.T0));
    assertFalse(fx.consumeReplay.hasSeen(b.envelopeId()));
  }

  /**
   * Interleaving harness over the REAL {@link InMemorySequenceStore} — no mock.
   * When armed via {@link #raceOnNextRead()}, the next {@code lastSequence}
   * read also commits the observed-next sequence to the underlying store, as a
   * concurrently racing consumer would, before returning the originally
   * observed value. All mutation paths delegate to the real atomic store.
   */
  private static final class RacingSequenceStore implements JCustosEventSequenceStore {

    private final InMemorySequenceStore delegate = new InMemorySequenceStore();
    private final AtomicBoolean race = new AtomicBoolean();

    void raceOnNextRead() {
      race.set(true);
    }

    @Override
    public Optional<EventSequence> lastSequence(TenantId tenantId, EventProducerId producerId) {
      Optional<EventSequence> observed = delegate.lastSequence(tenantId, producerId);
      if (race.compareAndSet(true, false)) {
        EventSequence competing = observed.map(EventSequence::next).orElse(EventSequence.FIRST);
        delegate.updateSequence(tenantId, producerId, competing);
      }
      return observed;
    }

    @Override
    public void updateSequence(TenantId tenantId, EventProducerId producerId,
        EventSequence sequence) {
      delegate.updateSequence(tenantId, producerId, sequence);
    }

    @Override
    public EventSequence reserveNext(TenantId tenantId, EventProducerId producerId) {
      return delegate.reserveNext(tenantId, producerId);
    }

    @Override
    public boolean compareAndAdvance(TenantId tenantId, EventProducerId producerId,
        Optional<EventSequence> expectedLast, EventSequence newSequence) {
      return delegate.compareAndAdvance(tenantId, producerId, expectedLast, newSequence);
    }
  }
}
