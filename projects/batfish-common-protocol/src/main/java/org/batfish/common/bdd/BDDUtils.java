package org.batfish.common.bdd;

import static com.google.common.base.Preconditions.checkArgument;

import com.google.common.collect.ImmutableSet;
import java.util.Arrays;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import net.sf.javabdd.BDD;
import net.sf.javabdd.BDDFactory;
import net.sf.javabdd.BDDPairing;
import net.sf.javabdd.BDDVarPair;
import net.sf.javabdd.JFactory;
import org.batfish.datamodel.IpProtocol;

/** Various utility methods for working with {@link BDD}s. */
public class BDDUtils {
  /** Create a new {@link BDDFactory} object with {@code numVariables} boolean variables. */
  public static BDDFactory bddFactory(int numVariables) {
    BDDFactory factory = JFactory.init(10000, 1000);
    factory.setCacheRatio(64);
    factory.setVarNum(numVariables); // reserve 32 1-bit variables
    return factory;
  }

  public static BDD[] bitvector(BDDFactory factory, int length, int start, boolean reverse) {
    checkArgument(factory.varNum() >= start + length, "Not enough variables to create bitvector");
    BDD[] bitvec = new BDD[length];
    for (int i = 0; i < length; i++) {
      int idx;
      if (reverse) {
        idx = start + length - i - 1;
      } else {
        idx = start + i;
      }
      bitvec[i] = factory.ithVar(idx);
    }
    return bitvec;
  }

  public static BDD[] concatBitvectors(BDD[]... arrays) {
    return Arrays.stream(arrays).flatMap(Arrays::stream).toArray(BDD[]::new);
  }

  /** Create a {@link BDDPairing} for swapping variables. */
  public static BDDPairing swapPairing(BDDFactory bddFactory, Set<BDDVarPair> varPairs) {
    checkArgument(!varPairs.isEmpty(), "Cannot build swapPairing for empty bitvectors");

    return bddFactory.getPair(
        varPairs.stream()
            .flatMap(pair -> Stream.of(pair, new BDDVarPair(pair.getNewVar(), pair.getOldVar())))
            .collect(ImmutableSet.toImmutableSet()));
  }

  /** Create a {@link BDDPairing} for swapping variables. */
  public static BDDPairing swapPairing(BDD[] bv1, BDD[] bv2) {
    checkArgument(bv1.length > 0, "Cannot build swapPairing for empty bitvectors");
    checkArgument(bv1.length == bv2.length, "Bitvector lengths must be equal");

    return bv1[0]
        .getFactory()
        .getPair(
            IntStream.range(0, bv1.length)
                .mapToObj(
                    i -> Stream.of(new BDDVarPair(bv1[i], bv2[i]), new BDDVarPair(bv2[i], bv1[i])))
                .flatMap(Function.identity())
                .collect(ImmutableSet.toImmutableSet()));
  }

  /**
   * Checks that the given BDD obeys packet invariants about which fields can be tested
   * independently vs must be tested together (e.g., ICMP Code should only be tested if this is an
   * ICMP packet).
   */
  public static boolean aclHasPacketInvariants(BDDPacket pkt, BDD aclBdd) {
    // TCP Flags should only be set for TCP packets
    BDD tcp = pkt.getIpProtocol().value(IpProtocol.TCP);
    BDD notTcp = tcp.not().andEq(aclBdd);
    boolean tcpOk =
        !notTcp.testsVars(pkt.getTcpAck())
            && !notTcp.testsVars(pkt.getTcpCwr())
            && !notTcp.testsVars(pkt.getTcpEce())
            && !notTcp.testsVars(pkt.getTcpFin())
            && !notTcp.testsVars(pkt.getTcpPsh())
            && !notTcp.testsVars(pkt.getTcpRst())
            && !notTcp.testsVars(pkt.getTcpSyn())
            && !notTcp.testsVars(pkt.getTcpUrg());
    notTcp.free();
    tcp.free();
    if (!tcpOk) {
      return false;
    }

    // ICMP type/code should only be set for ICMP packets
    BDD icmp = pkt.getIpProtocol().value(IpProtocol.ICMP);
    BDD notIcmp = icmp.not().andEq(aclBdd);
    boolean icmpOk =
        !notIcmp.testsVars(pkt.getIcmpType().getBDDInteger().getVars())
            && !notIcmp.testsVars(pkt.getIcmpCode().getBDDInteger().getVars());
    notIcmp.free();
    icmp.free();
    if (!icmpOk) {
      return false;
    }

    // Ports should only be set for protocols with ports
    BDD[] portProtocols =
        IpProtocol.IP_PROTOCOLS_WITH_PORTS.stream()
            .map(pkt.getIpProtocol()::value)
            .toArray(BDD[]::new);
    BDD ports = pkt.getFactory().orAllAndFree(portProtocols);
    BDD notPorts = ports.not().andEq(aclBdd);
    BDD srcPort = pkt.getSrcPort().getVars();
    BDD dstPort = pkt.getDstPort().getVars();
    boolean portsOk = !notPorts.testsVars(srcPort) && !notPorts.testsVars(dstPort);
    notPorts.free();
    ports.free();
    if (!portsOk) {
      return false;
    }

    return true;
  }
}
