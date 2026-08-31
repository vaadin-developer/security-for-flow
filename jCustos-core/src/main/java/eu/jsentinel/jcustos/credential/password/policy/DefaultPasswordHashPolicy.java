/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.password.policy;

import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashFormatVersion;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Reference {@link PasswordHashPolicy} backed by explicit, immutable
 * maps. Use {@link #builder()} to assemble a policy programmatically.
 *
 * <p>The class deliberately does not provide a "load from properties"
 * facility in Phase 1a: policies live in code so they participate in
 * type checking and tests.</p>
 */
public final class DefaultPasswordHashPolicy implements PasswordHashPolicy {

  private final int policyVersion;
  private final PasswordHashFormatVersion preferredFormatVersion;
  private final String preferredAlgorithm;
  private final String preferredProviderId;
  private final Set<String> acceptableAlgorithms;
  private final Set<String> acceptableProviderIds;
  private final Map<String, Map<String, String>> defaultsByAlgorithm;
  private final Map<String, Map<String, String>> minByAlgorithm;
  private final Map<String, Map<String, String>> maxByAlgorithm;
  private final Set<Integer> rejectedFormatVersions;
  private final Set<Integer> rejectedPolicyVersions;

  private DefaultPasswordHashPolicy(Builder b) {
    this.policyVersion = b.policyVersion;
    this.preferredFormatVersion = Objects.requireNonNull(
        b.preferredFormatVersion, "preferredFormatVersion");
    this.preferredAlgorithm = Objects.requireNonNull(
        b.preferredAlgorithm, "preferredAlgorithm");
    this.preferredProviderId = Objects.requireNonNull(
        b.preferredProviderId, "preferredProviderId");
    this.acceptableAlgorithms = Collections.unmodifiableSet(
        new LinkedHashSet<>(b.acceptableAlgorithms));
    this.acceptableProviderIds = Collections.unmodifiableSet(
        new LinkedHashSet<>(b.acceptableProviderIds));
    this.defaultsByAlgorithm = freeze(b.defaultsByAlgorithm);
    this.minByAlgorithm = freeze(b.minByAlgorithm);
    this.maxByAlgorithm = freeze(b.maxByAlgorithm);
    this.rejectedFormatVersions = Set.copyOf(b.rejectedFormatVersions);
    this.rejectedPolicyVersions = Set.copyOf(b.rejectedPolicyVersions);

    if (policyVersion < 1) {
      throw new IllegalArgumentException("policyVersion must be >= 1");
    }
    if (!acceptableAlgorithms.contains(preferredAlgorithm)) {
      throw new IllegalArgumentException(
          "preferred algorithm is not in the acceptable set");
    }
    if (!acceptableProviderIds.contains(preferredProviderId)) {
      throw new IllegalArgumentException(
          "preferred provider id is not in the acceptable set");
    }
    for (String alg : acceptableAlgorithms) {
      if (!defaultsByAlgorithm.containsKey(alg)
          || !minByAlgorithm.containsKey(alg)
          || !maxByAlgorithm.containsKey(alg)) {
        throw new IllegalArgumentException(
            "policy is missing defaults/min/max for an acceptable algorithm");
      }
    }
  }

  private static Map<String, Map<String, String>> freeze(
      Map<String, Map<String, String>> source) {
    Map<String, Map<String, String>> out = new LinkedHashMap<>();
    for (Map.Entry<String, Map<String, String>> e : source.entrySet()) {
      out.put(e.getKey(),
          Collections.unmodifiableMap(new LinkedHashMap<>(e.getValue())));
    }
    return Collections.unmodifiableMap(out);
  }

  @Override
  public int policyVersion() {
    return policyVersion;
  }

  @Override
  public PasswordHashFormatVersion preferredFormatVersion() {
    return preferredFormatVersion;
  }

  @Override
  public String preferredAlgorithm() {
    return preferredAlgorithm;
  }

  @Override
  public String preferredProviderId() {
    return preferredProviderId;
  }

  @Override
  public Set<String> acceptableAlgorithms() {
    return acceptableAlgorithms;
  }

  @Override
  public Set<String> acceptableProviderIds() {
    return acceptableProviderIds;
  }

  @Override
  public boolean isAlgorithmAcceptable(String algorithm) {
    return acceptableAlgorithms.contains(algorithm);
  }

  @Override
  public boolean isProviderAcceptable(String providerId) {
    return acceptableProviderIds.contains(providerId);
  }

  @Override
  public Map<String, String> defaultParameters(String algorithm) {
    Map<String, String> m = defaultsByAlgorithm.get(algorithm);
    if (m == null) {
      throw new PasswordHashValidationException(
          "no default parameters configured for algorithm");
    }
    return m;
  }

  @Override
  public Map<String, String> minimumParameters(String algorithm) {
    Map<String, String> m = minByAlgorithm.get(algorithm);
    if (m == null) {
      throw new PasswordHashValidationException(
          "no minimum parameters configured for algorithm");
    }
    return m;
  }

  @Override
  public Set<Integer> rejectedFormatVersions() {
    return rejectedFormatVersions;
  }

  @Override
  public Set<Integer> rejectedPolicyVersions() {
    return rejectedPolicyVersions;
  }

  @Override
  public Map<String, String> maximumParameters(String algorithm) {
    Map<String, String> m = maxByAlgorithm.get(algorithm);
    if (m == null) {
      throw new PasswordHashValidationException(
          "no maximum parameters configured for algorithm");
    }
    return m;
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Mutable assembler. The resulting policy is fully immutable.
   */
  public static final class Builder {
    private int policyVersion = 1;
    private PasswordHashFormatVersion preferredFormatVersion =
        PasswordHashFormatVersion.CURRENT;
    private String preferredAlgorithm;
    private String preferredProviderId;
    private final Set<String> acceptableAlgorithms = new LinkedHashSet<>();
    private final Set<String> acceptableProviderIds = new LinkedHashSet<>();
    private final Map<String, Map<String, String>> defaultsByAlgorithm =
        new LinkedHashMap<>();
    private final Map<String, Map<String, String>> minByAlgorithm =
        new LinkedHashMap<>();
    private final Map<String, Map<String, String>> maxByAlgorithm =
        new LinkedHashMap<>();
    private final Set<Integer> rejectedFormatVersions = new LinkedHashSet<>();
    private final Set<Integer> rejectedPolicyVersions = new LinkedHashSet<>();

    private Builder() { }

    public Builder policyVersion(int v) {
      this.policyVersion = v;
      return this;
    }

    public Builder preferredFormatVersion(PasswordHashFormatVersion v) {
      this.preferredFormatVersion = v;
      return this;
    }

    public Builder preferredAlgorithm(String a) {
      this.preferredAlgorithm = a;
      this.acceptableAlgorithms.add(a);
      return this;
    }

    public Builder preferredProviderId(String p) {
      this.preferredProviderId = p;
      this.acceptableProviderIds.add(p);
      return this;
    }

    public Builder addAcceptableAlgorithm(String a) {
      this.acceptableAlgorithms.add(a);
      return this;
    }

    public Builder addAcceptableProviderId(String p) {
      this.acceptableProviderIds.add(p);
      return this;
    }

    public Builder defaultParameters(String algorithm, Map<String, String> params) {
      this.defaultsByAlgorithm.put(algorithm, new LinkedHashMap<>(params));
      return this;
    }

    public Builder minimumParameters(String algorithm, Map<String, String> params) {
      this.minByAlgorithm.put(algorithm, new LinkedHashMap<>(params));
      return this;
    }

    public Builder maximumParameters(String algorithm, Map<String, String> params) {
      this.maxByAlgorithm.put(algorithm, new LinkedHashMap<>(params));
      return this;
    }

    /**
     * Marks an envelope format wire value as explicitly rejected.
     * Stored envelopes whose {@code formatVersion} appears here fail
     * validation outright (CWE-693).
     */
    public Builder rejectFormatVersion(int wireValue) {
      this.rejectedFormatVersions.add(wireValue);
      return this;
    }

    /**
     * Marks an envelope policy version as explicitly rejected. Stored
     * envelopes whose {@code policyVersion} appears here fail
     * validation outright.
     */
    public Builder rejectPolicyVersion(int policyVersion) {
      this.rejectedPolicyVersions.add(policyVersion);
      return this;
    }

    public DefaultPasswordHashPolicy build() {
      return new DefaultPasswordHashPolicy(this);
    }
  }
}
