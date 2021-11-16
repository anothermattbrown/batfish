package org.batfish.datamodel;

import static com.google.common.base.MoreObjects.firstNonNull;
import static com.google.common.base.Preconditions.checkArgument;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableList;
import java.io.Serializable;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

/** Configuration tracking for VRF leaking that should happen from all source VRFs. */
@ParametersAreNonnullByDefault
public class VrfLeakConfig implements Serializable {

  /**
   * VRF leak configs describing how routes should leak between BGP RIBs. Guaranteed empty if {@link
   * #getLeakAsBgp()} is not set
   */
  @JsonProperty(PROP_BGP_VRF_LEAK_CONFIGS)
  @Nonnull
  public List<BgpVrfLeakConfig> getBgpVrfLeakConfigs() {
    return _bgpVrfLeakConfigs;
  }

  public void addBgpVrfLeakConfig(@Nonnull BgpVrfLeakConfig c) {
    checkArgument(_leakAsBgp, "BGP VRF leak configs cannot be configured unless leakAsBgp is set");
    _bgpVrfLeakConfigs =
        ImmutableList.<BgpVrfLeakConfig>builder().addAll(_bgpVrfLeakConfigs).add(c).build();
  }

  /**
   * Whether the node containing this leak configuration leaks routes between BGP RIBs or main RIBs.
   *
   * <p>If leaking as BGP, {@link #getMainRibVrfLeakConfigs()} is guaranteed to be empty, and
   * otherwise {@link #getBgpVrfLeakConfigs} is guaranteed to be empty.
   *
   * <p>For those familiar with vendor semantics: if set to {@code true}, leaking routes as BGP is
   * equivalent to IOS vrf leaking which is done between BGP RIBs of different VRFs (on a real
   * device, via VPNv4 address family). If set to {@code false}, the leaking process more closely
   * follows the Juniper model, where routes are simply copied from the main RIB of one routing
   * instance (read: VRF) into another, with appropriate src-VRF annotation.
   */
  @JsonProperty(PROP_LEAK_AS_BGP)
  public boolean getLeakAsBgp() {
    return _leakAsBgp;
  }

  /**
   * VRF leak configs describing how routes should leak between main RIBs. Guaranteed empty if
   * {@link #getLeakAsBgp()} is set
   */
  @JsonProperty(PROP_MAIN_RIB_VRF_LEAK_CONFIGS)
  @Nonnull
  public List<MainRibVrfLeakConfig> getMainRibVrfLeakConfigs() {
    return _mainRibVrfLeakConfigs;
  }

  public void addMainRibVrfLeakConfig(@Nonnull MainRibVrfLeakConfig c) {
    checkArgument(
        !_leakAsBgp, "Main RIB VRF leak configs cannot be configured when leakAsBgp is set");
    _mainRibVrfLeakConfigs =
        ImmutableList.<MainRibVrfLeakConfig>builder().addAll(_mainRibVrfLeakConfigs).add(c).build();
  }

  public static Builder builder(boolean leakAsBgp) {
    return new Builder(leakAsBgp);
  }

  @Override
  public boolean equals(@Nullable Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof VrfLeakConfig)) {
      return false;
    }
    VrfLeakConfig that = (VrfLeakConfig) o;
    return _leakAsBgp == that._leakAsBgp
        && _bgpVrfLeakConfigs.equals(that._bgpVrfLeakConfigs)
        && _mainRibVrfLeakConfigs.equals(that._mainRibVrfLeakConfigs);
  }

  @Override
  public int hashCode() {
    return Objects.hash(_leakAsBgp, _bgpVrfLeakConfigs, _mainRibVrfLeakConfigs);
  }

  public VrfLeakConfig(boolean leakAsBgp) {
    this(leakAsBgp, ImmutableList.of(), ImmutableList.of());
  }

  private VrfLeakConfig(
      boolean leakAsBgp,
      List<BgpVrfLeakConfig> bgpVrfLeakConfigs,
      List<MainRibVrfLeakConfig> mainRibVrfLeakConfigs) {
    if (leakAsBgp) {
      checkArgument(
          mainRibVrfLeakConfigs.isEmpty(),
          "Main RIB VRF leak configs cannot be configured when leakAsBgp is set");
    } else {
      checkArgument(
          bgpVrfLeakConfigs.isEmpty(),
          "BGP VRF leak configs cannot be configured unless leakAsBgp is set");
    }
    _leakAsBgp = leakAsBgp;
    _bgpVrfLeakConfigs = ImmutableList.copyOf(bgpVrfLeakConfigs);
    _mainRibVrfLeakConfigs = ImmutableList.copyOf(mainRibVrfLeakConfigs);
  }

  @JsonCreator
  private static VrfLeakConfig create(
      @Nullable @JsonProperty(PROP_BGP_VRF_LEAK_CONFIGS) List<BgpVrfLeakConfig> bgpVrfLeakConfigs,
      @Nullable @JsonProperty(PROP_LEAK_AS_BGP) Boolean leakAsBgp,
      @Nullable @JsonProperty(PROP_MAIN_RIB_VRF_LEAK_CONFIGS)
          List<MainRibVrfLeakConfig> mainRibVrfLeakConfigs) {
    return new VrfLeakConfig(
        firstNonNull(leakAsBgp, false),
        firstNonNull(bgpVrfLeakConfigs, ImmutableList.of()),
        firstNonNull(mainRibVrfLeakConfigs, ImmutableList.of()));
  }

  private static final String PROP_BGP_VRF_LEAK_CONFIGS = "bgpVrfLeakConfigs";
  private static final String PROP_LEAK_AS_BGP = "leakAsBgp";
  private static final String PROP_MAIN_RIB_VRF_LEAK_CONFIGS = "mainRibVrfLeakConfigs";

  private final boolean _leakAsBgp;
  private @Nonnull List<BgpVrfLeakConfig> _bgpVrfLeakConfigs;
  private @Nonnull List<MainRibVrfLeakConfig> _mainRibVrfLeakConfigs;

  public static final class Builder {

    public Builder addBgpVrfLeakConfig(@Nonnull BgpVrfLeakConfig c) {
      _bgpVrfLeakConfigs.add(c);
      return this;
    }

    public Builder addMainRibVrfLeakConfig(@Nonnull MainRibVrfLeakConfig c) {
      _mainRibVrfLeakConfigs.add(c);
      return this;
    }

    public VrfLeakConfig build() {
      return new VrfLeakConfig(
          _leakAsBgp, _bgpVrfLeakConfigs.build(), _mainRibVrfLeakConfigs.build());
    }

    private Builder(boolean leakAsBgp) {
      _leakAsBgp = leakAsBgp;
    }

    private final boolean _leakAsBgp;
    private @Nonnull ImmutableList.Builder<BgpVrfLeakConfig> _bgpVrfLeakConfigs =
        ImmutableList.builder();
    private @Nonnull ImmutableList.Builder<MainRibVrfLeakConfig> _mainRibVrfLeakConfigs =
        ImmutableList.builder();
  }
}