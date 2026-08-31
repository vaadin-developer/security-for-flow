package eu.jsentinel.jcustos.events.bus;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
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

import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import eu.jsentinel.jcustos.events.api.SignedJSentinelEventEnvelope;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.codec.RecordReflectionCanonicalizer;
import eu.jsentinel.jcustos.events.keys.InMemoryKeyManagement;
import eu.jsentinel.jcustos.events.keys.JSentinelEventSigningKeyProvider;
import eu.jsentinel.jcustos.events.keys.SigningKeySnapshot;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

@DisplayName("PublishPipeline — signing-key snapshot under rotation (R00)")
class PublishPipelineKeyRotationTest {

  /**
   * Adversarial decorator over the REAL {@link InMemoryKeyManagement} — no
   * mock. Every read of {@link #currentKeyId()} triggers a rotation before
   * returning, the exact interleave that used to produce envelopes stamped
   * keyId=OLD but signed with NEW private material when the pipeline read the
   * three getters separately. {@link #signingSnapshot()} forwards to the
   * delegate's atomic snapshot and rotates AFTERWARDS, modeling a rotation
   * landing right after the pipeline captured its one snapshot.
   */
  private static final class RotateOnReadProvider implements JSentinelEventSigningKeyProvider {

    private final InMemoryKeyManagement delegate;
    private final AtomicInteger rotations = new AtomicInteger();

    private RotateOnReadProvider(InMemoryKeyManagement delegate) {
      this.delegate = delegate;
    }

    @Override
    public KeyId currentKeyId() {
      KeyId id = delegate.currentKeyId();
      rotate();
      return id;
    }

    @Override
    public PrivateKey currentSigningKey() {
      return delegate.currentSigningKey();
    }

    @Override
    public SignatureAlgorithm currentAlgorithm() {
      return delegate.currentAlgorithm();
    }

    @Override
    public SigningKeySnapshot signingSnapshot() {
      SigningKeySnapshot snapshot = delegate.signingSnapshot();
      rotate();
      return snapshot;
    }

    private void rotate() {
      delegate.rotate(KeyId.of("rotated-" + rotations.incrementAndGet()));
    }
  }

  @Test
  @DisplayName("every envelope verifies under its own stamped keyId even when rotation interleaves")
  void envelopeConsistentUnderInterleavedRotation() {
    BusFixtures fx = new BusFixtures();
    RotateOnReadProvider provider = new RotateOnReadProvider(fx.keyManagement);
    PublishPipeline publisher = new PublishPipeline(provider,
        new RecordReflectionCanonicalizer(), new CanonicalJsonPayloadCodec(),
        PayloadHashAlgorithm.SHA_256, BusFixtures.PRODUCER, fx.publishSequence,
        fx.publishReplay, fx.allowAll, Duration.ofMinutes(5), () -> BusFixtures.T0);
    ConsumePipeline consumer = fx.consumePipeline();

    // Each publish interleaves with a rotation; each envelope must still be a
    // consistent (keyId, signature) pair — Valid end-to-end, because the
    // rotated-out key stays accepted for verification.
    for (int i = 0; i < 3; i++) {
      SignedJSentinelEventEnvelope envelope = publisher.toEnvelope(BusFixtures.event());
      JSentinelEventVerificationResult result = consumer.verify(envelope, BusFixtures.T0);
      assertInstanceOf(JSentinelEventVerificationResult.Valid.class, result,
          "envelope stamped " + envelope.keyId().value()
              + " must verify under its own stamped keyId");
    }
  }

  @Test
  @DisplayName("premise check: separately-read keyId + signing key DO break under this interleave")
  void separateGetterReadsWouldBreak() {
    // Documents that the harness is genuinely adversarial: composing the three
    // getters the way the pipeline did before R00 yields an id/key mismatch.
    BusFixtures fx = new BusFixtures();
    RotateOnReadProvider provider = new RotateOnReadProvider(fx.keyManagement);

    KeyId stamped = provider.currentKeyId(); // rotates before returning
    byte[] data = "base".getBytes(StandardCharsets.UTF_8);
    byte[] signature = provider.currentAlgorithm().sign(data, provider.currentSigningKey());
    PublicKey stampedKey = fx.keyManagement.resolveVerificationKey(stamped).orElseThrow();
    assertFalse(provider.currentAlgorithm().verify(data, signature, stampedKey),
        "the R00 bug shape: stamped id and signing key from separate reads must NOT match");
  }
}
