package eu.jsentinel.jcustos.credential.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.credential.password.rehash.RehashDecisionEngine;
import eu.jsentinel.jcustos.credential.password.dummy.DummyVerificationContext;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashCodec;
import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;
import eu.jsentinel.jcustos.credential.password.pepper.PepperReference;
import eu.jsentinel.jcustos.credential.password.limiter.NoLimitKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashValidator;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashParameterValidatorRegistry;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.provider.PasswordHashProviderRegistry;
import eu.jsentinel.jcustos.credential.password.dummy.DummyVerificationService;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterValidator;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2PasswordHashProvider;
import eu.jsentinel.jcustos.credential.password.pepper.NoOpPepperService;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * CWE-208: the dummy KDF runs the preferred algorithm, so verifying a hash on
 * some other algorithm used to cost a different amount — measurable from
 * outside, and enough to tell "existing but unmigrated" from "no such user".
 * That is the one thing the dummy path exists to hide.
 */
@DisplayName("Verification cost floor across a lazy KDF migration (CWE-208)")
class KdfCostFloorTest {

  /** Records which dummy runs happened, so the floor can be observed. */
  private static final class RecordingDummyService implements DummyVerificationService {
    private final DummyVerificationService delegate;
    private final List<DummyVerificationContext> runs = new ArrayList<>();

    RecordingDummyService(DummyVerificationService delegate) {
      this.delegate = delegate;
    }

    @Override
    public void runDummyKdf(char[] password, DummyVerificationContext context) {
      runs.add(context);
      delegate.runDummyKdf(password, context);
    }
  }

  private static PasswordHashPolicy policyPreferring(String algorithm, String providerId) {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    defaults.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    Map<String, String> min = new LinkedHashMap<>();
    min.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
    min.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    min.put(Pbkdf2ParameterNames.SALT_LENGTH, "16");
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Pbkdf2ParameterNames.ITERATIONS, "2000");
    max.put(Pbkdf2ParameterNames.KEY_LENGTH, "64");
    max.put(Pbkdf2ParameterNames.SALT_LENGTH, "64");
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(algorithm)
        .preferredProviderId(providerId)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
        .build();
  }


  /**
   * A second, really-working provider under a different id — the shape of a
   * migration in progress, where the old provider must stay registered to
   * verify what it wrote while the new one takes over hashing.
   */
  private static final class RenamedPbkdf2Provider implements PasswordHashProvider {
    static final String PROVIDER_ID = "pbkdf2-next";
    private final Pbkdf2PasswordHashProvider delegate = new Pbkdf2PasswordHashProvider();

    @Override
    public String providerId() {
      return PROVIDER_ID;
    }

    @Override
    public String algorithm() {
      return Pbkdf2ParameterNames.ALGORITHM;
    }

    @Override
    public PasswordHashResult hash(char[] password, PasswordHashPolicy hashPolicy,
        Optional<PepperReference> pepper) {
      return delegate.hash(password, hashPolicy, pepper);
    }

    @Override
    public ProviderVerificationResult verify(char[] password, PasswordHashEnvelope envelope,
        Optional<PepperReference> pepper) {
      return delegate.verify(password, envelope, pepper);
    }
  }

  private record Fixture(DefaultPasswordHashingService service, RecordingDummyService dummy) {
  }

  private static Fixture serviceWith(PasswordHashPolicy policy) {
    PasswordHashProviderRegistry registry = new PasswordHashProviderRegistry(
        List.of(new Pbkdf2PasswordHashProvider(), new RenamedPbkdf2Provider()));
    RecordingDummyService dummy = new RecordingDummyService(
        new eu.jsentinel.jcustos.credential.password.dummy.DefaultDummyVerificationService(
            registry, policy, PasswordHashCodec.DEFAULT));
    DefaultPasswordHashingService service = new DefaultPasswordHashingService(
        PasswordHashCodec.DEFAULT,
        new DefaultPasswordHashValidator(new PasswordHashParameterValidatorRegistry(
            List.of(new Pbkdf2ParameterValidator()))),
        registry,
        NoOpPepperService.INSTANCE,
        policy,
        new RehashDecisionEngine(),
        NoLimitKdfExecutionLimiter.INSTANCE,
        dummy);
    return new Fixture(service, dummy);
  }

  @Test
  @DisplayName("a hash on the preferred algorithm needs no extra work")
  void preferredAlgorithmNeedsNoFloor() {
    PasswordHashPolicy policy =
        policyPreferring(Pbkdf2ParameterNames.ALGORITHM, Pbkdf2ParameterNames.PROVIDER_ID);
    Fixture fixture = serviceWith(policy);
    PasswordHashResult hashed = fixture.service().hash("hunter2".toCharArray());

    fixture.service().verify("hunter2".toCharArray(), hashed.encodedHash());

    assertEquals(List.of(), fixture.dummy().runs,
        "paying for a second KDF when the costs already match would be waste");
  }

  @Test
  @DisplayName("a wrong password against the preferred algorithm stays on one KDF")
  void wrongPasswordOnPreferredAlgorithmNeedsNoFloor() {
    PasswordHashPolicy policy =
        policyPreferring(Pbkdf2ParameterNames.ALGORITHM, Pbkdf2ParameterNames.PROVIDER_ID);
    Fixture fixture = serviceWith(policy);
    PasswordHashResult hashed = fixture.service().hash("hunter2".toCharArray());

    fixture.service().verify("wrong".toCharArray(), hashed.encodedHash());

    assertEquals(List.of(), fixture.dummy().runs,
        "a mismatch on the preferred algorithm already costs the preferred amount");
  }

  @Test
  @DisplayName("a hash on a non-preferred algorithm is topped up to the preferred cost")
  void nonPreferredAlgorithmGetsCostFloor() {
    // Hash under a policy preferring PBKDF2 …
    PasswordHashPolicy migrationSource =
        policyPreferring(Pbkdf2ParameterNames.ALGORITHM, Pbkdf2ParameterNames.PROVIDER_ID);
    PasswordHashResult legacyHash =
        serviceWith(migrationSource).service().hash("hunter2".toCharArray());

    // … then verify under a policy that has moved on to a different provider id,
    // which is what a lazy migration looks like from the verifier's side.
    PasswordHashPolicy afterMigration =
        policyPreferring(Pbkdf2ParameterNames.ALGORITHM, RenamedPbkdf2Provider.PROVIDER_ID);
    Fixture fixture = serviceWith(afterMigration);

    fixture.service().verify("hunter2".toCharArray(), legacyHash.encodedHash());

    assertTrue(fixture.dummy().runs.contains(
            DummyVerificationContext.NON_PREFERRED_ALGORITHM_COST_FLOOR),
        "an unmigrated account must not be cheaper to probe than an unknown one, runs="
            + fixture.dummy().runs);
  }
}
