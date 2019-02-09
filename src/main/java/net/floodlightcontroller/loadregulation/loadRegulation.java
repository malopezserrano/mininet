package net.floodlightcontroller.loadregulation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.types.MacVlanPair;
import net.floodlightcontroller.debugcounter.IDebugCounter;
import net.floodlightcontroller.debugcounter.IDebugCounterService;
import net.floodlightcontroller.debugcounter.IDebugCounterService.MetaData;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.util.FlowModUtils;
import net.floodlightcontroller.util.OFMessageUtils;

import net.floodlightcontroller.core.IListener;

import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionSetQueue;
import org.projectfloodlight.openflow.protocol.action.OFActionEnqueue;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionPushVlan;
import org.projectfloodlight.openflow.protocol.action.OFActionSetVlanVid;
import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.PacketType;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.util.LRULinkedHashMap;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class loadRegulation implements IOFMessageListener, IFloodlightModule {

      private IDebugCounter counterFlowMod;

      // Stores the learned state for each switch
      protected Map<IOFSwitch, Map<MacVlanPair, OFPort>> macVlanToSwitchPortMap;

      // flow-mod - for use in the cookie
      public static final int LEARNING_SWITCH_APP_ID = 1;
      // LOOK! This should probably go in some class that encapsulates
      // the app cookie management
      public static final int APP_ID_BITS = 12;
      public static final int APP_ID_SHIFT = (64 - APP_ID_BITS);
      public static final long LEARNING_SWITCH_COOKIE = (long) (LEARNING_SWITCH_APP_ID & ((1 << APP_ID_BITS) - 1)) << APP_ID_SHIFT;

      // more flow-mod defaults
      protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 100; // in seconds
      protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
      protected static short FLOWMOD_PRIORITY = 100;

      // flow remove
      protected static boolean FLOWMOD_DEFAULT_SET_SEND_FLOW_REM_FLAG = true;

      // for managing load thresholds
      protected static final int MAX_MACS_PER_SWITCH  = 10;
      protected static final int MAX_MACS_PER_SWITCH_PORT_LOW_OPERATION  = 1;
      protected static final int MAX_MACS_PER_SWITCH_PORT_HIGH_OPERATION  = 2;
      protected static final int MAX_MACS_PER_SWITCH_PORT_CRITICAL_OPERATION  = 3;
      protected enum Level {LOW, HIGH, CRITICAL};
      protected static boolean ENABLE_LOAD_REGULATION = true;

      protected IFloodlightProviderService floodlightProvider;
      protected Set macAddresses;
      protected static Logger logger;

      DatapathId switch1 = DatapathId.of("00:00:00:00:00:00:00:01");
      DatapathId ap1 = DatapathId.of("10:00:00:00:00:00:00:01");

  @Override
      public String getName() {
          // TODO Auto-generated method stub
          return loadRegulation.class.getSimpleName();
      }

      @Override
      public boolean isCallbackOrderingPrereq(OFType type, String name) {
          // TODO Auto-generated method stub
          return false;
     }

      @Override
      public boolean isCallbackOrderingPostreq(OFType type, String name) {
          // TODO Auto-generated method stub
          return false;
      }

      @Override
      public Collection<Class<? extends IFloodlightService>> getModuleServices() {
          // TODO Auto-generated method stub
            Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
            l.add(IFloodlightProviderService.class);
            return null;
      }

      @Override
      public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
          // TODO Auto-generated method stub
          return null;
      }

      @Override
      public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
          // TODO Auto-generated method stub
          return null;
      }

      @Override
      public void init(FloodlightModuleContext context) throws FloodlightModuleException {
          // TODO Auto-generated method stub
          floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
          macAddresses = new ConcurrentSkipListSet<Long>();
          macVlanToSwitchPortMap = new ConcurrentHashMap<IOFSwitch, Map<MacVlanPair, OFPort>>();
          logger = LoggerFactory.getLogger(loadRegulation.class);
      }

      @Override
      public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
          // TODO Auto-generated method stub
          if (ENABLE_LOAD_REGULATION) {
	  floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	  floodlightProvider.addOFMessageListener(OFType.FLOW_REMOVED, this);
	  floodlightProvider.addOFMessageListener(OFType.ERROR, this);
          }
      }

      @Override
      public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        if (sw.getId().equals(switch1)) {
          logger.error("loadRegulation is not executed for switch {}", sw);
          return Command.CONTINUE;
        } else {
          switch (msg.getType()) {
            case PACKET_IN:
              logger.info("received a packet-in {} from switch {}", msg, sw);
              return this.processPacketInMessage(sw, (OFPacketIn) msg, cntx);
            case FLOW_REMOVED:
              logger.info("received a flow-removed {} from switch {}", msg, sw);
              return this.processFlowRemovedMessage(sw, (OFFlowRemoved) msg);
            case ERROR:
              logger.info("received an error {} from switch {}", msg, sw);
              return Command.CONTINUE;
            default:
              logger.error("received an unexpected message {} from switch {}", msg, sw);
              return Command.CONTINUE;
          }
          }
      }

  private Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
          OFPort inPort = OFMessageUtils.getInPort(pi);

          // Packet-in is only processed for upload traffic
          if (inPort.getPortNumber()==6) {
            logger.info("packet-in received from wired interface on switch {}", sw);
          } else {
            logger.info("packet-in received from wirelesss interface on switch {}", sw);
            /* Read packet header attributes into Match */

            Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
            VlanVid vlan = VlanVid.ofVlan(eth.getVlanID()) == null ? VlanVid.ZERO : VlanVid.ofVlan(eth.getVlanID());
            MacAddress srcMac = eth.getSourceMACAddress();
            MacAddress dstMac = eth.getDestinationMACAddress();

            Match.Builder mb = sw.getOFFactory().buildMatch();
            mb.setExact(MatchField.IN_PORT, inPort)
	          .setExact(MatchField.ETH_SRC, srcMac)
	          .setExact(MatchField.ETH_DST, dstMac);

            if (srcMac == null) {
               srcMac = MacAddress.NONE;
            }
            if (dstMac == null) {
               dstMac = MacAddress.NONE;
            }
            if (vlan == null) {
               vlan = VlanVid.ZERO;
            }

            if ((srcMac.getLong() & 0x010000000000L) == 0) {
            // If source MAC is a unicast address, learn the port for this MAC/VLAN
            logger.info("Añado MAC {} a switch {}", srcMac, sw);
            this.addToPortMap(sw, srcMac, vlan, inPort);
            }

            setFlow (sw, mb, inPort);
        }
        return Command.CONTINUE;
      }

      public void setFlow (IOFSwitch sw, Match.Builder mb, OFPort inPort){
          Match m = mb.build();
          Match.Builder mbp = m.createBuilder();
          mbp.setExact(MatchField.IN_PORT, inPort);
          mbp.setExact(MatchField.ETH_SRC, mb.get(MatchField.ETH_SRC));
          VlanVid vlanVid = VlanVid.ZERO;
          //logger.info("IN PORT {} SELECCION DE VLAN",inPort.getPortNumber());
          mbp.setExact(MatchField.ETH_TYPE, EthType.IPv4);

switch (inPort.getPortNumber()) {
  case 2:
  switch (getAPLoadLevel(sw, inPort)) {
    case LOW:
      logger.info("LOW level Vlan selected 4 for in-port 2");
      vlanVid = VlanVid.ofVlan(4);
      this.writeFlowModVlan(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mbp.build(), inPort, vlanVid);
      break;
    case HIGH:
      logger.info("HIGH level Drop traffic for in-port 2");
      this.writeFlowModDrop(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mbp.build(), inPort);
      break;
    case CRITICAL:
      logger.info("CRITICAL level Drop traffic for in-port 2");
      this.writeFlowModDrop(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mbp.build(), inPort);
      break;
  }
    break;
  case 3:
  switch (getAPLoadLevel(sw, inPort)) {
    case LOW:
      logger.info("LOW level Vlan selected 2 for in-port 3");
      vlanVid = VlanVid.ofVlan(2);
      this.writeFlowModVlan(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mbp.build(), inPort, vlanVid);
      break;
    case HIGH:
      logger.info("HIGH level Vlan selected 3 for in-port 3");
      vlanVid = VlanVid.ofVlan(3);
      this.writeFlowModVlan(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mbp.build(), inPort, vlanVid);
      break;
    case CRITICAL:
      logger.info("CRITICAL level Drop traffic for in-port 3");
      this.writeFlowModDrop(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mbp.build(), inPort);
      break;
  }
    break;
  case 4:
  switch (getAPLoadLevel(sw, inPort)) {
    case LOW:
      logger.info("LOW level Vlan selected 3 for in-port 4");
      vlanVid = VlanVid.ofVlan(3);
      this.writeFlowModVlan(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mbp.build(), inPort, vlanVid);
      break;
    case HIGH:
      logger.info("HIGH level Vlan selected 4 for in-port 4");
      vlanVid = VlanVid.ofVlan(4);
      this.writeFlowModVlan(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mbp.build(), inPort, vlanVid);
      break;
    case CRITICAL:
      logger.info("CRITICAL level Drop traffic for in-port 4");
      this.writeFlowModDrop(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mbp.build(), inPort);
      break;
  }
    break;
  case 5:
  switch (getAPLoadLevel(sw, inPort)) {
    case LOW:
      logger.info("LOW level Vlan selected 4 for in-port 5");
      vlanVid = VlanVid.ofVlan(4);
      this.writeFlowModVlan(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mbp.build(), inPort, vlanVid);
      break;
    case HIGH:
      logger.info("HIGH level Drop traffic for in-port 5");
      this.writeFlowModDrop(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mbp.build(), inPort);
      break;
    case CRITICAL:
      logger.info("CRITICAL level Drop traffic for in-port 5");
      this.writeFlowModDrop(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mbp.build(), inPort);
      break;
  }
    break;
}


/*
          switch (inPort.getPortNumber()) {
            case 2:
              logger.info("Vlan selected 4 for in-port 2");
              vlanVid = VlanVid.ofVlan(4);
              break;
            case 3:
              if (getAPLoadLevel(sw, inPort) == Level.LOW) {
                logger.info("LOW level Vlan selected 2 for in-port 3");
                vlanVid = VlanVid.ofVlan(2);
              } else if {
                logger.info("HIGH/CRITICAL level Vlan selected 3 for in-port 3");
                vlanVid = VlanVid.ofVlan(3); 
              }
              break;
            case 4:
              if (getAPLoadLevel(sw, inPort) == Level.LOW) {
                logger.info("LOW level Vlan selected 3 for in-port 4");
                vlanVid = VlanVid.ofVlan(3);
              } else {
                logger.info("HIGH/CRITICAL level Vlan selected 4 for in-port 4");
                vlanVid = VlanVid.ofVlan(4);
              }
              break;
            case 5:
              logger.info("Vlan selected 4 for in-port 5");
              vlanVid = VlanVid.ofVlan(4);
              break;
          }
*/
          //mbp.setExact(MatchField.ETH_TYPE, EthType.IPv4);
          //this.writeFlowModVlan(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mbp.build(), inPort, vlanVid);
      }

  /**
   * Processes a flow removed message. We will delete the learned MAC/VLAN mapping from
   * the switch's table.
   * @param sw The switch that sent the flow removed message.
   * @param flowRemovedMessage The flow removed message.
   * @return Whether to continue processing this message or stop.
   */
  private Command processFlowRemovedMessage(IOFSwitch sw, OFFlowRemoved flowRemovedMessage) {
      if (!flowRemovedMessage.getCookie().equals(U64.of(loadRegulation.LEARNING_SWITCH_COOKIE))) {
          return Command.CONTINUE;
      }
      logger.trace("{} flow entry removed {}", sw, flowRemovedMessage);
      Match match = flowRemovedMessage.getMatch();
      OFPort inPort = match.get(MatchField.IN_PORT);

      if (match.get(MatchField.ETH_SRC)== null) {
          logger.info("Flow remove sin MAC"); 
          return Command.CONTINUE;
      } else {
      this.removeFromPortMap(sw, match.get(MatchField.ETH_SRC),
          match.get(MatchField.VLAN_VID) == null
          ? VlanVid.ZERO
          : match.get(MatchField.VLAN_VID).getVlanVid());

      //Match.Builder mb = sw.getOFFactory().buildMatch();
      //setFlow (sw, mb, inPort);
      }
      return Command.CONTINUE;
  }

  /**
   * Writes a OFFlowMod to a switch.
   * @param sw The switch tow rite the flowmod to.
   * @param command The FlowMod actions (add, delete, etc).
   * @param bufferId The buffer ID if the switch has buffered the packet.
   * @param match The OFMatch structure to write.
   * @param outPort The switch port to output it to.
   */
  private void writeFlowModVlan(IOFSwitch sw, OFFlowModCommand command, OFBufferId bufferId, Match match, OFPort outPort, VlanVid vlanVid) {

    OFFlowMod.Builder fmb;
    if (command == OFFlowModCommand.DELETE) {
        fmb = sw.getOFFactory().buildFlowDelete();
    } else {
      fmb = sw.getOFFactory().buildFlowAdd();
    }
    fmb.setMatch(match);
    fmb.setCookie((U64.of(loadRegulation.LEARNING_SWITCH_COOKIE)));
    fmb.setIdleTimeout(loadRegulation.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
    fmb.setHardTimeout(loadRegulation.FLOWMOD_DEFAULT_HARD_TIMEOUT);
    fmb.setPriority(loadRegulation.FLOWMOD_PRIORITY);
    fmb.setBufferId(bufferId);
    fmb.setOutPort((command == OFFlowModCommand.DELETE) ? OFPort.ANY : outPort);

    ArrayList<OFAction> actions = new ArrayList<OFAction>();

    OFActionPushVlan setVlanPush = sw.getOFFactory().actions().buildPushVlan()
      .setEthertype(EthType.VLAN_FRAME)
      .build();
    actions.add(setVlanPush);

  	OFActionSetVlanVid.Builder ab = OFFactories.getFactory(OFVersion.OF_10).actions().buildSetVlanVid();
  	ab.setVlanVid(vlanVid);
  	logger.debug("action {}", ab.build());
  	actions.add(ab.build());

    OFActionOutput output = sw.getOFFactory().actions().buildOutput()
      .setMaxLen(0xFFffFFff)
      .setPort(OFPort.of(6))
      .build();
    actions.add(output);

   if (FLOWMOD_DEFAULT_SET_SEND_FLOW_REM_FLAG) {
       Set<OFFlowModFlags> flags = new HashSet<OFFlowModFlags>();
       flags.add(OFFlowModFlags.SEND_FLOW_REM);
       fmb.setFlags(flags);
   }

    FlowModUtils.setActions(fmb, actions, sw);
    logger.info("{} {} flow mod {}",new Object[]{ sw, (command == OFFlowModCommand.DELETE) ? "deleting" : "adding", fmb.build() });

    // and write it out
    sw.write(fmb.build());
  }

private void writeFlowModDrop(IOFSwitch sw, OFFlowModCommand command, OFBufferId bufferId, Match match, OFPort outPort) {

    OFFlowMod.Builder fmb;
    if (command == OFFlowModCommand.DELETE) {
        fmb = sw.getOFFactory().buildFlowDelete();
    } else {
      fmb = sw.getOFFactory().buildFlowAdd();
    }
    fmb.setMatch(match);
    fmb.setCookie((U64.of(loadRegulation.LEARNING_SWITCH_COOKIE)));
    fmb.setIdleTimeout(loadRegulation.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
    fmb.setHardTimeout(loadRegulation.FLOWMOD_DEFAULT_HARD_TIMEOUT);
    fmb.setPriority(loadRegulation.FLOWMOD_PRIORITY);
    fmb.setBufferId(bufferId);
    fmb.setOutPort((command == OFFlowModCommand.DELETE) ? OFPort.ANY : outPort);

    ArrayList<OFAction> actions = new ArrayList<OFAction>();

    if (FLOWMOD_DEFAULT_SET_SEND_FLOW_REM_FLAG) {
       Set<OFFlowModFlags> flags = new HashSet<OFFlowModFlags>();
       flags.add(OFFlowModFlags.SEND_FLOW_REM);
       fmb.setFlags(flags);
   }

    FlowModUtils.setActions(fmb, actions, sw);
    logger.info("{} {} flow mod {}",new Object[]{ sw, (command == OFFlowModCommand.DELETE) ? "deleting" : "adding", fmb.build() });

    // and write it out
    sw.write(fmb.build());
}

public Level getAPLoadLevel(IOFSwitch sw, OFPort inPort) {
    if (macsPerSwitch(sw) < MAX_MACS_PER_SWITCH) {
      if (macsPerSwitchPort(sw,inPort) < MAX_MACS_PER_SWITCH_PORT_HIGH_OPERATION) {
        return Level.LOW;
      } else if (macsPerSwitchPort(sw,inPort) < MAX_MACS_PER_SWITCH_PORT_CRITICAL_OPERATION) {
          return Level.HIGH;
        } else {
            return Level.CRITICAL;
          }
    }
      return Level.CRITICAL;
  }

  public int macsPerSwitch(IOFSwitch sw) {
    Map<MacVlanPair, OFPort> swMap;
    try {
      swMap = macVlanToSwitchPortMap.get(sw);
    }
    catch (Exception e) {
      logger.info ("Switch {} no registrado", sw);
      return 0;
    }
    return swMap.size();
  }

  public int macsPerSwitchPort(IOFSwitch sw, OFPort port ) {
    Map<MacVlanPair, OFPort> swMap = macVlanToSwitchPortMap.get(sw);
    int counter = 0;

    for (Map.Entry<MacVlanPair, OFPort> entry : swMap.entrySet()) {
      MacVlanPair key = entry.getKey();
      OFPort value = entry.getValue();
      if (value.equals(port)) {
        counter ++;
      }
    }
    return counter;
  }

  /**
   * Clears the MAC/VLAN -> SwitchPort map for all switches
   */
  public void clearLearnedTable() {
    macVlanToSwitchPortMap.clear();
  }

  /**
   * Clears the MAC/VLAN -> SwitchPort map for a single switch
   * @param sw The switch to clear the mapping for
   */
  public void clearLearnedTable(IOFSwitch sw) {
    Map<MacVlanPair, OFPort> swMap = macVlanToSwitchPortMap.get(sw);
    if (swMap != null) {
      swMap.clear();
    }
  }

  public void printTable(Map<IOFSwitch, Map<MacVlanPair, OFPort>> map) {
    for (IOFSwitch key : map.keySet()) {
      logger.info("key {} value {}", key.toString(), map.get(key));
    }
  }

  /**
   * Get the port that a MAC/VLAN pair is associated with
   * @param sw The switch to get the mapping from
   * @param mac The MAC address to get
   * @param vlan The VLAN number to get
   * @return The port the host is on
   */
  public OFPort getFromPortMap(IOFSwitch sw, MacAddress mac, VlanVid vlan) {
    if (vlan == VlanVid.FULL_MASK || vlan == null) {
      vlan = VlanVid.ofVlan(0);
    }
    try {
      Map<MacVlanPair, OFPort> swMap = macVlanToSwitchPortMap.get(sw);
    if (swMap != null) {
      return swMap.get(new MacVlanPair(mac, vlan));
    }
    }
    catch (Exception e) {
      logger.info ("Exception en sw{}", sw);
      return null;
    }
    // if none found
    return null;
  }

  /**
   * Adds a host to the MAC/VLAN->SwitchPort mapping
   * @param sw The switch to add the mapping to
   * @param mac The MAC address of the host to add
   * @param vlan The VLAN that the host is on
   * @param portVal The switchport that the host is on
   */
  protected void addToPortMap(IOFSwitch sw, MacAddress mac, VlanVid vlan, OFPort portVal) {
    Map<MacVlanPair, OFPort> swMap = macVlanToSwitchPortMap.get(sw);

    if (vlan == VlanVid.FULL_MASK || vlan == null) {
      vlan = VlanVid.ofVlan(0);
    }

    if (swMap == null) {
      // May be accessed by REST API so we need to make it thread safe
      swMap = Collections.synchronizedMap(new LRULinkedHashMap<MacVlanPair, OFPort>(MAX_MACS_PER_SWITCH));
      macVlanToSwitchPortMap.put(sw, swMap);
    }
    swMap.put(new MacVlanPair(mac, vlan), portVal);
        logger.info("MAC Address: {} added on switch: {}",
              mac.toString(),
              sw.getId().toString());
    printTable(macVlanToSwitchPortMap);
    logger.info("Switch: {} contiene {} MACs after Packet-in",sw, (macsPerSwitch(sw)));
    logger.info("puerto {} contiene {} MACs after Packet-in",portVal, (macsPerSwitchPort(sw,portVal)));
  }

  /**
   * Removes a host from the MAC/VLAN->SwitchPort mapping
   * @param sw The switch to remove the mapping from
   * @param mac The MAC address of the host to remove
   * @param vlan The VLAN that the host is on
   */
  protected void removeFromPortMap(IOFSwitch sw, MacAddress mac, VlanVid vlan) {
    OFPort portVal = getFromPortMap(sw,mac,vlan);
    if (vlan == VlanVid.FULL_MASK) {
      vlan = VlanVid.ofVlan(0);
    }

    Map<MacVlanPair, OFPort> swMap = macVlanToSwitchPortMap.get(sw);
    if (swMap != null) {
      logger.info("mac :{}, vlan:{}",mac,vlan);
      swMap.remove(new MacVlanPair(mac, vlan));
      logger.info("MAC Address: {} removed on switch: {}",mac.toString(),sw.getId().toString());
    }
    printTable(macVlanToSwitchPortMap);
    logger.info("Switch: {} contiene {} MACs after Flow-Remove",sw, (macsPerSwitch(sw)));
    logger.info("puerto {} contiene {} MACs after Flow-Remove", portVal, macsPerSwitchPort(sw,portVal));
  }

}
