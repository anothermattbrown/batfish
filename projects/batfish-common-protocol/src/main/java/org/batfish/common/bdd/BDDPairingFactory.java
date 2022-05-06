package org.batfish.common.bdd;

import static org.batfish.common.bdd.BDDUtils.concatBitvectors;
import static org.batfish.common.bdd.BDDUtils.pairing;
import static org.batfish.common.bdd.BDDUtils.swapPairing;
import static org.parboiled.common.Preconditions.checkArgument;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Stream;
import javax.annotation.Nullable;
import net.sf.javabdd.BDD;
import net.sf.javabdd.BDDFactory;
import net.sf.javabdd.BDDPairing;

public final class BDDPairingFactory {
  private final BDD[] _domain;
  private final BDD[] _codomain;
  private final BDD _domainVars;

  // lazy init
  @Nullable BDDPairing _swapPairing;
  @Nullable BDDPairing _primeToUnprimePairing;

  /* cache to uniquify BDDPairingFactories
   * each one creates a swapPairing. BDDFactory does not uniquify pairings, so we won't get caching
   * if we create duplicates!
   * TODO leaks!
   */
  private static BDDFactory CACHE_FACTORY;
  private static final Map<BDD, BDDPairingFactory> CACHE = new HashMap<>();

  @VisibleForTesting
  BDDPairingFactory(BDD[] domain, BDD[] codomain, BDD domainVars) {
    checkArgument(domain.length == codomain.length, "domain and codomain must have equal size");
    checkArgument(domain.length > 0, "domain and codomain must contain at least one variable");
    checkArgument(hasDistinctElements(domain), "domain must have distinct variables");
    checkArgument(hasDistinctElements(codomain), "codomain must have distinct variables");
    checkArgument(
        Sets.intersection(Sets.newHashSet(domain), Sets.newHashSet(codomain)).isEmpty(),
        "domain and codomain must be disjoint");
    _domain = domain;
    _codomain = codomain;
    _domainVars = domainVars;
  }

  public static BDDPairingFactory create(BDD[] domain, BDD[] codomain) {
    BDDFactory factory = domain[0].getFactory();
    BDD domainVars = factory.andAll(domain);
    if (CACHE_FACTORY != factory) {
      CACHE.clear();
      CACHE_FACTORY = factory;
    }
    return CACHE.computeIfAbsent(domainVars, vars -> new BDDPairingFactory(domain, codomain, vars));
  }

  private static boolean hasDistinctElements(BDD[] vars) {
    return Arrays.stream(vars).distinct().count() == vars.length;
  }

  /** Create a {@link BDDPairing} that swaps domain and codomain variables. */
  public BDDPairing getSwapPairing() {
    if (_swapPairing == null) {
      _swapPairing = swapPairing(_domain, _codomain);
    }
    return _swapPairing;
  }

  /** Create a {@link BDDPairing} that maps codomain variables to domain variables. */
  public BDDPairing getPrimeToUnprimePairing() {
    if (_primeToUnprimePairing == null) {
      _primeToUnprimePairing = pairing(_codomain, _domain);
    }
    return _primeToUnprimePairing;
  }

  public BDDPairingFactory composeWith(BDDPairingFactory other) {
    return BDDPairingFactory.create(
        concatBitvectors(_domain, other._domain), concatBitvectors(_codomain, other._codomain));
  }

  public BDD identityRelation(Predicate<BDD> includeDomainVar) {
    BDD rel = _domainVars.getFactory().one();
    for (int i = _domain.length - 1; i >= 0; i--) {
      if (includeDomainVar.test(_domain[i])) {
        rel.andWith(_domain[i].biimp(_codomain[i]));
      }
    }
    return rel;
  }

  public boolean domainIncludes(BDD var) {
    for (int i = 0; i < _domain.length; i++) {
      if (_domain[i].equals(var)) {
        return true;
      }
    }
    return false;
  }

  public BDDPairingFactory union(BDDPairingFactory other) {
    if (this.equals(other)) {
      return this;
    }
    BDD[] domain =
        Stream.of(_domain, other._domain).flatMap(Arrays::stream).distinct().toArray(BDD[]::new);
    BDD[] codomain =
        Stream.of(_codomain, other._codomain)
            .flatMap(Arrays::stream)
            .distinct()
            .toArray(BDD[]::new);
    return BDDPairingFactory.create(domain, codomain);
  }

  public static BDDPairingFactory union(List<BDDPairingFactory> factories) {
    BDD[] domain =
        factories.stream()
            .flatMap(factory -> Arrays.stream(factory._domain))
            .distinct()
            .toArray(BDD[]::new);
    BDD[] codomain =
        factories.stream()
            .flatMap(factory -> Arrays.stream(factory._codomain))
            .distinct()
            .toArray(BDD[]::new);
    return BDDPairingFactory.create(domain, codomain);
  }

  /**
   * Return a {@link BDD} of the variables in the pairing's domain, suitable for use with {@link
   * BDD#exist(BDD)}. The caller owns the {@link BDD} and must free it.
   */
  public BDD getDomainVarsBdd() {
    return _domainVars.id(); // defensive copy
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof BDDPairingFactory)) {
      return false;
    }
    BDDPairingFactory that = (BDDPairingFactory) o;
    // only consider domainVars, since 1) the domain is a function of it, and 2) the codomain is a
    // function of the domain (assuming no accidental variable reuse, etc).
    assert !_domainVars.equals(that._domainVars)
        || (ImmutableSet.copyOf(_domain).equals(ImmutableSet.copyOf(that._domain))
            && ImmutableSet.copyOf(_codomain).equals(ImmutableSet.copyOf(that._codomain)));
    return _domainVars.equals(that._domainVars);
  }

  @Override
  public int hashCode() {
    return _domainVars.hashCode();
  }

  public boolean includes(BDDPairingFactory pairingFactory) {
    return Arrays.stream(pairingFactory._domain).allMatch(this::domainIncludes);
  }
}
