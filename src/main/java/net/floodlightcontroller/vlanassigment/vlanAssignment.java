package net.floodlightcontroller.vlanassignment;

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

public class vlanAssignment implements IOFMessageListener, IFloodlightModule {

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
      protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 500; // in seconds
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
      protected enum APP {WEB, STREAMING, UNKNOWN};

      protected IFloodlightProviderService floodlightProvider;
      protected Set macAddresses;
      protected static Logger logger;

      DatapathId switch1 = DatapathId.of("00:00:00:00:00:00:00:01");

  @Override
      public String getName() {
          // TODO Auto-generated method stub
          return vlanAssignment.class.getSimpleName();
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
          logger = LoggerFactory.getLogger(vlanAssignment.class);
      }

      @Override
      public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
          // TODO Auto-generated method stub
          floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	  floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	  floodlightProvider.addOFMessageListener(OFType.FLOW_REMOVED, this);
	  floodlightProvider.addOFMessageListener(OFType.ERROR, this);
      }

      @Override
      public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        if (sw.getId().equals(switch1)) {
          logger.error("vlanAssignment is not executed for switch {}", sw);
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

        	 // if (!vlan.equals(VlanVid.ZERO)) {
        	 //   mb.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(vlan));
        	 // }

            if (srcMac == null) {
               srcMac = MacAddress.NONE;
            }
            if (dstMac == null) {
               dstMac = MacAddress.NONE;
            }
            if (vlan == null) {
               vlan = VlanVid.ZERO;
            }

            setFlowVlan (sw, mb, inPort);
        }
        return Command.CONTINUE;
      }

      public void setFlowVlan (IOFSwitch sw, Match.Builder mb, OFPort inPort){
          Match m = mb.build();
          Match.Builder mbp = m.createBuilder();
          mbp.setExact(MatchField.IN_PORT, inPort);
          VlanVid vlanVid = VlanVid.ZERO;
          logger.info("IN PORT {} SELECCION DE VLAN",inPort.getPortNumber());
          switch (inPort.getPortNumber()) {
            case 2:
              logger.info("Vlan selected 4 for in-port 2");
              vlanVid = VlanVid.ofVlan(4);
              //mbp.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(VlanVid.ofVlan(4)));
              break;
            case 3:
              logger.info("Vlan selected 2 for in-port 3");
              vlanVid = VlanVid.ofVlan(2);
              //mbp.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(VlanVid.ofVlan(2)));
              break;
            case 4:
              logger.info("Vlan selected 3 for in-port 4");
              vlanVid = VlanVid.ofVlan(3);
              //mbp.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(VlanVid.ofVlan(3)));
              break;
            case 5:
              logger.info("Vlan selected 4 for in-port 5");
              vlanVid = VlanVid.ofVlan(4);
              //mbp.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(VlanVid.ofVlan(4)));
              break;
          }

          mbp.setExact(MatchField.ETH_TYPE, EthType.IPv4);
          this.writeFlowMod(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mbp.build(), inPort, vlanVid);
      }

  /**
   * Processes a flow removed message. We will delete the learned MAC/VLAN mapping from
   * the switch's table.
   * @param sw The switch that sent the flow removed message.
   * @param flowRemovedMessage The flow removed message.
   * @return Whether to continue processing this message or stop.
   */
  private Command processFlowRemovedMessage(IOFSwitch sw, OFFlowRemoved flowRemovedMessage) {
      if (!flowRemovedMessage.getCookie().equals(U64.of(vlanAssignment.LEARNING_SWITCH_COOKIE))) {
          return Command.CONTINUE;
      }
      logger.trace("{} flow entry removed {}", sw, flowRemovedMessage);
      Match match = flowRemovedMessage.getMatch();
      OFPort inPort = match.get(MatchField.IN_PORT);

      Match.Builder mb = sw.getOFFactory().buildMatch();
      setFlowVlan (sw, mb, inPort);

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
  private void writeFlowMod(IOFSwitch sw, OFFlowModCommand command, OFBufferId bufferId, Match match, OFPort outPort, VlanVid vlanVid) {

    OFFlowMod.Builder fmb;
    if (command == OFFlowModCommand.DELETE) {
        fmb = sw.getOFFactory().buildFlowDelete();
    } else {
      fmb = sw.getOFFactory().buildFlowAdd();
    }
    fmb.setMatch(match);
    fmb.setCookie((U64.of(vlanAssignment.LEARNING_SWITCH_COOKIE)));
    fmb.setIdleTimeout(vlanAssignment.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
    fmb.setHardTimeout(vlanAssignment.FLOWMOD_DEFAULT_HARD_TIMEOUT);
    fmb.setPriority(vlanAssignment.FLOWMOD_PRIORITY);
    fmb.setBufferId(bufferId);
    fmb.setOutPort((command == OFFlowModCommand.DELETE) ? OFPort.ANY : outPort);

    ArrayList<OFAction> actions = new ArrayList<OFAction>();

    OFActionPushVlan setVlanPush = sw.getOFFactory().actions().buildPushVlan()
      //.pushVlan(EthType.VLAN_FRAME)
      .setEthertype(EthType.VLAN_FRAME)
      .build();
    actions.add(setVlanPush);

/*  OFActionSetVlanVid setVlanId = sw.getOFFactory().actions().buildSetVlanVid()
      .setVlanVid(vlanVid)
      .build();
    actions.add(setVlanId);
*/

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

}
