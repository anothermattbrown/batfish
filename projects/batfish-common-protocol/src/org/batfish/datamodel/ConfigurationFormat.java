package org.batfish.datamodel;

public enum ConfigurationFormat {
   ALCATEL_AOS("alcatel_aos"),
   ARISTA("arista"),
   AWS_VPC("aws_vpc"),
   BLADENETWORK("bladenetwork"),
   CISCO_IOS("cisco"),
   CISCO_IOS_XR("cisco"),
   CISCO_NX("cisco"),
   EMPTY("empty"),
   FLAT_JUNIPER("juniper"),
   FLAT_VYOS("vyos"),
   FORCE10("force10"),
   FOUNDRY("foundry"),
   HOST("host"),
   IGNORED("ignored"),
   IPTABLES("iptables"),
   JUNIPER("juniper"),
   JUNIPER_SWITCH("juniper"),
   MRV("mrv"),
   MSS("mss"),
   UNKNOWN("unknown"),
   VXWORKS("vxworks"),
   VYOS("vyos");

   private String _vendorString;

   private ConfigurationFormat(String vendorString) {
      _vendorString = vendorString;
   }

   public String getVendorString() {
      return _vendorString;
   }
}
