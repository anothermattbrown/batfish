package org.batfish.common.bdd;

import static org.batfish.common.bdd.BDDUtils.aclHasPacketInvariants;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import net.sf.javabdd.BDD;
import org.batfish.datamodel.IpProtocol;
import org.junit.Test;

public class BDDUtilsTest {
  @Test
  public void testAclHasPacketInvariants() {
    BDDPacket pkt = new BDDPacket();
    // The fullSat functions constrain every bit, so violate invariants.
    assertFalse(aclHasPacketInvariants(pkt, pkt.getFactory().one().fullSatOne()));
    assertFalse(aclHasPacketInvariants(pkt, pkt.getFactory().one().randomFullSatOne(7654321)));

    BDD icmp = pkt.getIpProtocol().value(IpProtocol.ICMP);
    BDD tcp = pkt.getIpProtocol().value(IpProtocol.TCP);
    BDD udp = pkt.getIpProtocol().value(IpProtocol.UDP);
    BDD ospf = pkt.getIpProtocol().value(IpProtocol.OSPF);
    BDD code5 = pkt.getIcmpCode().value(5);
    BDD type6 = pkt.getIcmpType().value(6);
    BDD dport7 = pkt.getDstPort().value(7);
    BDD sport8 = pkt.getSrcPort().value(8);
    BDD tcpFlag = pkt.getTcpAck();

    // Some valid packets
    assertTrue(aclHasPacketInvariants(pkt, icmp));
    assertTrue(aclHasPacketInvariants(pkt, icmp.and(type6).and(code5)));
    assertTrue(aclHasPacketInvariants(pkt, tcp));
    assertTrue(aclHasPacketInvariants(pkt, tcp.and(dport7).and(sport8).and(tcpFlag)));
    assertTrue(aclHasPacketInvariants(pkt, udp));
    assertTrue(aclHasPacketInvariants(pkt, udp.and(dport7).and(sport8)));
    assertTrue(aclHasPacketInvariants(pkt, ospf));

    // Some invalid packets
    assertFalse(aclHasPacketInvariants(pkt, icmp.and(dport7)));
    assertFalse(aclHasPacketInvariants(pkt, icmp.and(sport8)));
    assertFalse(aclHasPacketInvariants(pkt, icmp.and(tcpFlag)));
    assertFalse(aclHasPacketInvariants(pkt, udp.and(code5)));
    assertFalse(aclHasPacketInvariants(pkt, udp.and(type6)));
    assertFalse(aclHasPacketInvariants(pkt, udp.and(tcpFlag)));
    assertFalse(aclHasPacketInvariants(pkt, tcp.and(code5)));
    assertFalse(aclHasPacketInvariants(pkt, tcp.and(type6)));
    assertFalse(aclHasPacketInvariants(pkt, ospf.and(code5)));
    assertFalse(aclHasPacketInvariants(pkt, ospf.and(type6)));
    assertFalse(aclHasPacketInvariants(pkt, ospf.and(dport7)));
    assertFalse(aclHasPacketInvariants(pkt, ospf.and(sport8)));
    assertFalse(aclHasPacketInvariants(pkt, ospf.and(tcpFlag)));
  }
}
