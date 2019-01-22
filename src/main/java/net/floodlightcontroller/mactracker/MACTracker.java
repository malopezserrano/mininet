package net.floodlightcontroller.mactracker;

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
import net.floodlightcontroller.util.FlowModUtils;
import net.floodlightcontroller.util.OFMessageUtils;

import net.floodlightcontroller.core.IListener;

import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.projectfloodlight.openflow.util.LRULinkedHashMap;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class MACTracker implements IOFMessageListener, IFloodlightModule {

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
	protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 5; // in seconds
	protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
	protected static short FLOWMOD_PRIORITY = 100;
	// for managing our map sizes
	protected static final int MAX_MACS_PER_SWITCH  = 1000;

    	protected IFloodlightProviderService floodlightProvider;
    	protected Set macAddresses;
    	protected static Logger logger;
    	
	@Override
    	public String getName() {
        	// TODO Auto-generated method stub
        	return MACTracker.class.getSimpleName();
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
        	logger = LoggerFactory.getLogger(MACTracker.class);
    	}

    	@Override
    	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        	// TODO Auto-generated method stub
        	floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    	}

    	@Override
    	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
    		switch (msg.getType()) {
    		case PACKET_IN:
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

	private Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        	OFPort inPort = OFMessageUtils.getInPort(pi);
		logger.info("packet-in received on switch {}", sw);

        	/* Read packet header attributes into Match */
        	Match m = createMatchFromPacket(sw, inPort, cntx);
        	MacAddress sourceMac = m.get(MatchField.ETH_SRC);
        	MacAddress destMac = m.get(MatchField.ETH_DST);
        	VlanVid vlan = m.get(MatchField.VLAN_VID) == null ? VlanVid.ZERO : m.get(MatchField.VLAN_VID).getVlanVid();

        	if (sourceMac == null) {
          		sourceMac = MacAddress.NONE;
        	}
		if (destMac == null) {
          		destMac = MacAddress.NONE;
		}
        	if (vlan == null) {
          		vlan = VlanVid.ZERO;
        	}	

    		if ((sourceMac.getLong() & 0x010000000000L) == 0) {
    			// If source MAC is a unicast address, learn the port for this MAC/VLAN
    			this.addToPortMap(sw, sourceMac, vlan, inPort);
    		}

    		// Add flow table entry matching source MAC, dest MAC, VLAN and input port
    		// that sends to the port we previously learned for the dest MAC/VLAN.  Also
    		// add a flow table entry with source and destination MACs reversed, and
    		// input and output ports reversed.  When either entry expires due to idle
    		// timeout, remove the other one.  This ensures that if a device moves to
    		// a different port, a constant stream of packets headed to the device at
    		// its former location does not keep the stale entry alive forever.
    		// FIXME: current HP switches ignore DL_SRC and DL_DST fields, so we have to match on
    		// NW_SRC and NW_DST as well
    		// We write FlowMods with Buffer ID none then explicitly PacketOut the buffered packet

    		Match.Builder mb = m.createBuilder();
    		mb.setExact(MatchField.ETH_SRC, m.get(MatchField.ETH_DST))
    		.setExact(MatchField.ETH_DST, m.get(MatchField.ETH_SRC))
    		.setExact(MatchField.IN_PORT, inPort);
    		if (m.get(MatchField.VLAN_VID) != null) {
    			mb.setExact(MatchField.VLAN_VID, m.get(MatchField.VLAN_VID));
    		}

    		this.writeFlowMod(sw, OFFlowModCommand.ADD, OFBufferId.NO_BUFFER, mb.build(), inPort);

    		return Command.CONTINUE;
    	}

	/**
	 * Processes a flow removed message. We will delete the learned MAC/VLAN mapping from
	 * the switch's table.
	 * @param sw The switch that sent the flow removed message.
	 * @param flowRemovedMessage The flow removed message.
	 * @return Whether to continue processing this message or stop.
	 */
	private Command processFlowRemovedMessage(IOFSwitch sw, OFFlowRemoved flowRemovedMessage) {
		if (!flowRemovedMessage.getCookie().equals(U64.of(MACTracker.LEARNING_SWITCH_COOKIE))) {
    			return Command.CONTINUE;
  		}
		logger.trace("{} flow entry removed {}", sw, flowRemovedMessage);
  		Match match = flowRemovedMessage.getMatch();
  		// When a flow entry expires, it means the device with the matching source
  		// MAC address and VLAN either stopped sending packets or moved to a different
  		// port.  If the device moved, we can't know where it went until it sends
  		// another packet, allowing us to re-learn its port.  Meanwhile we remove
  		// it from the macVlanToPortMap to revert to flooding packets to this device.
  		this.removeFromPortMap(sw, match.get(MatchField.ETH_SRC),
      		match.get(MatchField.VLAN_VID) == null
      		? VlanVid.ZERO
      		: match.get(MatchField.VLAN_VID).getVlanVid());

		// Also, if packets keep coming from another device (e.g. from ping), the
		// corresponding reverse flow entry will never expire on its own and will
		// send the packets to the wrong port (the matching input port of the
		// expired flow entry), so we must delete the reverse entry explicitly.
		Match.Builder mb = sw.getOFFactory().buildMatch();
		mb.setExact(MatchField.ETH_SRC, match.get(MatchField.ETH_DST))
		.setExact(MatchField.ETH_DST, match.get(MatchField.ETH_SRC));
		if (match.get(MatchField.VLAN_VID) != null) {
			mb.setExact(MatchField.VLAN_VID, match.get(MatchField.VLAN_VID));
		}
		//this.writeFlowMod(sw, OFFlowModCommand.DELETE, OFBufferId.NO_BUFFER, mb.build(), match.get(MatchField.IN_PORT));
		return Command.CONTINUE;
	}	

	protected Match createMatchFromPacket(IOFSwitch sw, OFPort inPort, FloodlightContext cntx) {

		// The packet in match will only contain the port number.
		// We need to add in specifics for the hosts we're routing between.
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		VlanVid vlan = VlanVid.ofVlan(eth.getVlanID());
		MacAddress srcMac = eth.getSourceMACAddress();
		MacAddress dstMac = eth.getDestinationMACAddress();

		Match.Builder mb = sw.getOFFactory().buildMatch();
		mb.setExact(MatchField.IN_PORT, inPort)
		.setExact(MatchField.ETH_SRC, srcMac)
		.setExact(MatchField.ETH_DST, dstMac);

		if (!vlan.equals(VlanVid.ZERO)) {
			mb.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(vlan));
		}

		return mb.build();
	}

	/**
	 * Writes a OFFlowMod to a switch.
	 * @param sw The switch tow rite the flowmod to.
	 * @param command The FlowMod actions (add, delete, etc).
	 * @param bufferId The buffer ID if the switch has buffered the packet.
	 * @param match The OFMatch structure to write.
	 * @param outPort The switch port to output it to.
	 */
	private void writeFlowMod(IOFSwitch sw, OFFlowModCommand command, OFBufferId bufferId, Match match, OFPort outPort) {
	// from openflow 1.0 spec - need to set these on a struct ofp_flow_mod:
	// struct ofp_flow_mod {
	//    struct ofp_header header;
	//    struct ofp_match match; /* Fields to match */
	//    uint64_t cookie; /* Opaque controller-issued identifier. */
	//
	//    /* Flow actions. */
	//    uint16_t command; /* One of OFPFC_*. */
	//    uint16_t idle_timeout; /* Idle time before discarding (seconds). */
	//    uint16_t hard_timeout; /* Max time before discarding (seconds). */
	//    uint16_t priority; /* Priority level of flow entry. */
	//    uint32_t buffer_id; /* Buffered packet to apply to (or -1).
	//                           Not meaningful for OFPFC_DELETE*. */
	//    uint16_t out_port; /* For OFPFC_DELETE* commands, require
	//                          matching entries to include this as an
	//                          output port. A value of OFPP_NONE
	//                          indicates no restriction. */
	//    uint16_t flags; /* One of OFPFF_*. */
	//    struct ofp_action_header actions[0]; /* The action length is inferred
	//                                            from the length field in the
	//                                            header. */
	//    };

  	OFFlowMod.Builder fmb;
  	if (command == OFFlowModCommand.DELETE) {
    		fmb = sw.getOFFactory().buildFlowDelete();
  	} else {
    	fmb = sw.getOFFactory().buildFlowAdd();
  	}
  	fmb.setMatch(match);
  	fmb.setCookie((U64.of(MACTracker.LEARNING_SWITCH_COOKIE)));
  	fmb.setIdleTimeout(MACTracker.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
  	fmb.setHardTimeout(MACTracker.FLOWMOD_DEFAULT_HARD_TIMEOUT);
  	fmb.setPriority(MACTracker.FLOWMOD_PRIORITY);
  	fmb.setBufferId(bufferId);
  	fmb.setOutPort((command == OFFlowModCommand.DELETE) ? OFPort.ANY : outPort);
  	Set<OFFlowModFlags> sfmf = new HashSet<OFFlowModFlags>();
  	if (command != OFFlowModCommand.DELETE) {
    		sfmf.add(OFFlowModFlags.SEND_FLOW_REM);
  	}
  	fmb.setFlags(sfmf);


  	// set the ofp_action_header/out actions:
    	// from the openflow 1.0 spec: need to set these on a struct ofp_action_output:
  	// uint16_t type; /* OFPAT_OUTPUT. */
  	// uint16_t len; /* Length is 8. */
  	// uint16_t port; /* Output port. */
  	// uint16_t max_len; /* Max length to send to controller. */
  	// type/len are set because it is OFActionOutput,
  	// and port, max_len are arguments to this constructor
  	List<OFAction> al = new ArrayList<OFAction>();
  	al.add(sw.getOFFactory().actions().buildOutput().setPort(outPort).setMaxLen(0xffFFffFF).build());

  	FlowModUtils.setActions(fmb, al, sw);

    	logger.info("{} {} flow mod {}",new Object[]{ sw, (command == OFFlowModCommand.DELETE) ? "deleting" : "adding", fmb.build() });

  	//counterFlowMod.increment();

  	// and write it out
  	sw.write(fmb.build());
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
	}

	/**
	 * Removes a host from the MAC/VLAN->SwitchPort mapping
	 * @param sw The switch to remove the mapping from
	 * @param mac The MAC address of the host to remove
	 * @param vlan The VLAN that the host is on
	 */
	protected void removeFromPortMap(IOFSwitch sw, MacAddress mac, VlanVid vlan) {
		if (vlan == VlanVid.FULL_MASK) {
			vlan = VlanVid.ofVlan(0);
		}

		Map<MacVlanPair, OFPort> swMap = macVlanToSwitchPortMap.get(sw);
		if (swMap != null) {
			swMap.remove(new MacVlanPair(mac, vlan));
      			logger.info("MAC Address: {} removed on switch: {}",
              		mac.toString(),
              		sw.getId().toString());
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
		Map<MacVlanPair, OFPort> swMap = macVlanToSwitchPortMap.get(sw);
		if (swMap != null) {
			return swMap.get(new MacVlanPair(mac, vlan));
		}
		// if none found
		return null;
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
}
