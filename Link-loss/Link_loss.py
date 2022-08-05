from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3, ether
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.lib import hub
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.lib.packet import packet, ethernet, arp, lldp, icmpv6, udp , in_proto,ipv4,ether_types
import datetime
from operator import attrgetter
import copy
#Exercise 1.1
flow_idle_timeout = 10 # idle timeout for the flow
import math

class Assignment2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    ##############################################################
    # MAC_table:   {dpid, {mac,port}}
    # ARP_table:   {dpid, {mac,IPv4}}
    # Topology_db: {dpid_src, {dpid_dst, [port_src,port_dst]}}
    # datapaths:   {dpid, dp}
    #
    def __init__(self, *args, **kwargs):
        super(Assignment2, self).__init__(*args, **kwargs)
        self.MAC_table = {}
        self.ARP_table = {}
        #
        self.Topology_db = {}
        self.network_changed_thread = None
        #
        self.datapaths = {}

        self.UDP_packet = {} # I use this to save the previous packet number
        
        self.loss_packet = {}
        
        self.isUpdate = False
        self.port_switch = {}
        self.switch_port_connect= []
        self.have_empty = False

        self.link_connection_switch = {} # I use this to filter the linke connection between switch
        self.port_out_group = []
        self.port_in_group = []
        self.switch_drop = {} # I use this to filter the drop action of switch

        self.estimate_link_loss= {}
    ##############################################################
    # Add action for "missing flow"
    #
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def action_for_missing_flow(self, ev):
        msg        = ev.msg
        dp         = msg.datapath
        ofp        = dp.ofproto
        ofp_parser = dp.ofproto_parser

        actions      = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        instructions = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        self.flow_add(dp, 0, 0, None, instructions)


    ##############################################################
    # Store and Map "Datapath" and "Datapath ID"
    #
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def StateChange(self, ev):
        dp   = ev.datapath
        dpid = dp.id

        if ev.state == MAIN_DISPATCHER:
            self.datapaths.setdefault(dpid,dp)
            self.UDP_packet.setdefault(dpid,{})
        if ev.state == DEAD_DISPATCHER:
            if (self.datapaths):
                self.datapaths.pop(dpid)
                self.UDP_packet.setdefault(dpid,{})
    ##############################################################
    # Handle PACKET-IN message
    #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp  = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        pkt = packet.Packet(msg.data)
        etherh = pkt.get_protocol(ethernet.ethernet)    # Ethernet header
        smac = etherh.src                               # source MAC address
        dmac = etherh.dst                               # destination MAC address
        pin  = msg.match['in_port']                     # port in
        pout = 0                                        # port out
        dpid = dp.id                                    # datapath id
        
        # ****
        # Ignore LLDP, ICMPv6 packets
        if pkt.get_protocol(lldp.lldp) or pkt.get_protocol(icmpv6.icmpv6):
            return
        
        #print("\nOFC receives Packet-In message from Datapath ID of {} --- Log at: {}".format(dpid,datetime.datetime.now()))

        # Learn source MAC address and port
        #    *** Only at the edge OFS
        self.MAC_table.setdefault(dpid,{})
        if (self.MAC_table[dpid].get(smac) != pin):
            self.MAC_table[dpid][smac] = pin
            #print("   - Updates MAC table: MAC={} <-> Port={}".format(smac,pin))

        # Exercise 2.2
        # Handle the ARP packet.
        #   1. Learn the MAC address <--> IPv4 Adrress (ARP table)
        #   2. If it is ARP request packet and the Requested IPv4 adrress is in ARP table,
        #         OFC creating the ARP reply anf forward to the End-Host via PacketOut message.
        
        ###########################################################################################
        # Error rate estimate
        #
        """
        First we will forward the first UDP packet ( inform the start - Port out : 65534) to controller and immediately implement 
        the flow rule instructing the next 10000 UDP packet (Port out: 65534) will be flooded to all port except the received port. 
        . When the switch received the UDP packet ( warning the end - Port out: 65535), the switch will forward
        it to controller - this is a sign that controller can send the Flow Stats Request Packet and 
        and start calculating the link loss.
        """
        if etherh.ethertype == ether_types.ETH_TYPE_IP:
            udp_packet = pkt.get_protocol(udp.udp)
            if udp_packet:
                #udp_src_port = udp_packet.src_port
                udp_dst_port = udp_packet.dst_port
                
                if udp_dst_port ==  65534:
                    for datapath in self.link_connection_switch.keys():
                        
                        if datapath in self.datapaths.keys():
                            dp = self.datapaths[datapath]
                            ofp_parser = dp.ofproto_parser
                            ofp = dp.ofproto
                            match_udp       =   ofp_parser.OFPMatch(eth_type=0x0800,ip_proto = in_proto.IPPROTO_UDP,udp_dst=udp_dst_port)
                            # Install the Flow Mod and Group Mod for the forwarding switch
                            if len(self.link_connection_switch[datapath]) < 2:    
                                actions_udp      = [ofp_parser.OFPActionOutput(self.link_connection_switch[datapath].values()[0][0])] 
                                instructions_udp    = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_udp)]
                                mod = ofp_parser.OFPFlowMod(datapath=dp, priority=2,idle_timeout = 40,
                                                    match=match_udp, instructions=instructions_udp)
                                dp.send_msg(mod)                                
                            else:
                                for next_switch in self.link_connection_switch[datapath]:
                                    port_out = self.link_connection_switch[datapath][next_switch][0]
                                    self.port_out_group.append(port_out)
                                    if len(self.port_out_group) == len(self.link_connection_switch[datapath]):          
                                        actions1 = [ofp_parser.OFPActionOutput(self.port_out_group[0])]
                                        actions2 = [ofp_parser.OFPActionOutput(self.port_out_group[1])]
                                        buckets = [ofp_parser.OFPBucket(actions=actions1),
                                                ofp_parser.OFPBucket(actions=actions2)]
                                        req = ofp_parser.OFPGroupMod(dp, ofp.OFPGC_ADD,
                                                                ofp.OFPGT_ALL, 50, buckets)
                                        dp.send_msg(req)

                                        actions = [ofp_parser.OFPActionGroup(group_id=50)]
                                        instructions_udp =[ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                                        mod = ofp_parser.OFPFlowMod(datapath=dp, priority = 2,idle_timeout = 40,
                                                    match=match_udp, instructions = instructions_udp)
                                        dp.send_msg(mod)
                                        self.port_out_group=[]
                                    #print( " Sending the Group Mod for adding the multicast entry port out {} in switch ID {}".)
                    for dpid in self.switch_drop.keys():
                        if dpid in self.datapaths.keys():
                            dp = self.datapaths[dpid]
                            ofp_parser = dp.ofproto_parser
                            ofp = dp.ofproto 
                            if len(self.switch_drop[dpid]) < 2:
                                match_udp_drop       =   ofp_parser.OFPMatch(eth_type=0x0800,ip_proto = in_proto.IPPROTO_UDP
                                                                        ,udp_dst=udp_dst_port,in_port=self.switch_drop[dpid].values()[0][0])
                                mod = ofp_parser.OFPFlowMod(datapath=dp, priority=3,idle_timeout = 40,
                                                            match=match_udp_drop)
                                dp.send_msg(mod)
                                
                            else:
                                for next_switch in self.switch_drop[dpid]:
                                    port_in = self.switch_drop[dpid][next_switch][0]
                                    self.port_in_group.append(port_in)
                                    if len(self.port_in_group) == len(self.switch_drop[dpid]):
                                        for i in range(len(self.port_in_group)):
                                            match_udp_drop_i =  ofp_parser.OFPMatch(eth_type=0x0800,ip_proto = in_proto.IPPROTO_UDP
                                                                        ,udp_dst=udp_dst_port,in_port=self.port_in_group[i])
                                            mod = ofp_parser.OFPFlowMod(datapath=dp, priority=3,idle_timeout = 40,
                                                            match=match_udp_drop_i)
                                            dp.send_msg(mod)
                                        self.port_in_group=[]


                      
                if udp_dst_port == 65535:
                    print("")
                    print("--------------------------------------------------------")
                    for dpid in self.link_connection_switch.keys():
                        if dpid in self.datapaths.keys():
                            dp = self.datapaths[dpid]
                            ofp_parser = dp.ofproto_parser
                            ofp = dp.ofproto
                            if len(self.link_connection_switch[dpid]) == 1:    
                                FlowStats_req = ofp_parser.OFPFlowStatsRequest(datapath= dp)
                                dp.send_msg(FlowStats_req)
                            else:
                                GroupStats_req = ofp_parser.OFPGroupStatsRequest(datapath=dp,flags = 0,group_id=50)
                                dp.send_msg(GroupStats_req)

                                hub.sleep(1) # wait 1 second
                                group_delete = ofp_parser.OFPGroupMod(dp,ofp.OFPGC_DELETE,
                                                                        ofp.OFPGT_ALL,50,None)
                                dp.send_msg(group_delete)
                    for dpid in self.switch_drop.keys():
                        if dpid in self.datapaths.keys():
                            dp = self.datapaths[dpid]
                            ofp_parser = dp.ofproto_parser
                            ofp = dp.ofproto    
                            FlowStats_req = ofp_parser.OFPFlowStatsRequest(datapath= dp)
                            dp.send_msg(FlowStats_req)
        #######################################################################################
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            _sip = arp_pkt.src_ip
            _dip = arp_pkt.dst_ip
            if arp_pkt.opcode == arp.ARP_REQUEST:
                print("   - Receives a ARP request packet from host {} ({}) asking MAC of {}".format(_sip,smac,_dip))

                # Update ARP Table
                self.ARP_table.setdefault(dpid,{})
                if (self.ARP_table[dpid].get(smac) != _sip):
                    self.ARP_table[dpid][smac] = _sip
                    print("      + Updates ARP table: MAC={} <-> IPv4={}".format(smac,_sip))
                
                have_arp_info = False

                # Create ARP reply packet and send it to the requested Host
                for _dpid in self.ARP_table.keys():
                    if _dip in self.ARP_table[_dpid].values():
                        for _dmac in self.ARP_table[_dpid].keys():
                            if self.ARP_table[_dpid][_dmac] == _dip:
                                break
                        
                        print("      + Creates and returns the ARP reply packet: IPv4={} <-> MAC={}".format(_dip,_dmac))
                        have_arp_info = True
                        
                        e = ethernet.ethernet(dst=smac, src=_dmac, ethertype=ether.ETH_TYPE_ARP)
                        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                                    src_mac=_dmac, src_ip=_dip,
                                    dst_mac=smac,  dst_ip=_sip)
                        p = packet.Packet()
                        p.add_protocol(e)
                        p.add_protocol(a)
                        p.serialize()

                        actions = [ofp_parser.OFPActionOutput(pin)]
                        out     = ofp_parser.OFPPacketOut(datapath=dp, 
                                                        buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, #***
                                                        actions=actions, data=p.data)
                        dp.send_msg(out)
                        break
                if (not have_arp_info):
                    print("      + {} is not in ARP table".format(_dip))
            return

        # If no entry in the ARP_table, return None
        # In this example, all nodes have to send at least one ARP request packet to help OFC built the ARP table
        dpid_dest = self.Get_dst_dpid(dmac)
        if dpid_dest == None:
            return
        
        print("   - DATA info: packet from {} to {}".format(smac,dmac))

        # Exercise 2.1 and Exercise 2.3
        # Find the best route and apply the entries to all switch on the flow
        path_route = self.FindRoute(dpid,dpid_dest)

        print("   - Add flow entries to all OFS on the path route")
        for i in range(len(path_route)):            
            _dp         = self.datapaths[path_route[i]]
            _ofp        = _dp.ofproto
            _ofp_parser = _dp.ofproto_parser
            
            if i < len(path_route)-1:
                _pout = self.Get_port_out(path_route[i],path_route[i+1],dmac)
            else:
                _pout = self.MAC_table[path_route[i]][dmac]
            
            if i==0:
                _pin = pin
                pout = _pout
            else:
                _pin = self.Get_port_out(path_route[i],path_route[i-1],dmac)

            # Exercise 2.3
            # Prepare and send FLOW MOD (add new enty to the OFS)
            # Forward
            _actions = [_ofp_parser.OFPActionOutput(_pout)]
            _inst    = [_ofp_parser.OFPInstructionActions(_ofp.OFPIT_APPLY_ACTIONS, _actions)]
            _match   = _ofp_parser.OFPMatch(eth_dst=dmac, in_port=_pin)
            self.flow_add(_dp, flow_idle_timeout, 1, _match, _inst)

            # Backward
            _actions = [_ofp_parser.OFPActionOutput(_pin)]
            _inst    = [_ofp_parser.OFPInstructionActions(_ofp.OFPIT_APPLY_ACTIONS, _actions)]
            _match   = _ofp_parser.OFPMatch(eth_dst=smac, in_port=_pout)
            self.flow_add(_dp, flow_idle_timeout, 1, _match, _inst)

        hub.sleep(0.01)
        # Prepare and send PACKET-OUT
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data  

        actions = [ofp_parser.OFPActionOutput(pout)]
        out     = ofp_parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=pin, actions=actions, data=data)
        print("   - OFC send PacketOut message to datapath ID of {}".format(dpid))
        print("      + DATA info: packet from {} to {}".format(smac,dmac))
        dp.send_msg(out)   
    ##############################################################
    # Flow Stats Reply Handler
    #
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        self.have_empty = False
        body = ev.msg.body
        self.logger.info('datapath         '
                         'in-port'
                         '  out-port packets  bytes')
        self.logger.info('---------------- '
                         '--------  '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 2],
                           key=lambda flow: (flow.match['udp_dst'])):
                self.logger.info('%016x  %8d %8x %8d %8d',
                             ev.msg.datapath.id,
                             0,stat.instructions[0].actions[0].port ,
                             stat.packet_count, stat.byte_count)
                if ev.msg.datapath.id in self.UDP_packet.keys():
                    self.UDP_packet[ev.msg.datapath.id][stat.instructions[0].actions[0].port]=stat.packet_count
        for stat in sorted([flow for flow in body if flow.priority == 3],
                           key=lambda flow: (flow.match['in_port'])):
                self.logger.info('%016x  %8x %8d %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'],0 ,
                             stat.packet_count, stat.byte_count)
                if ev.msg.datapath.id in self.UDP_packet.keys():
                    self.UDP_packet[ev.msg.datapath.id][stat.match['in_port']]=stat.packet_count
        n_switches = self.num_switches()
        for dp in self.UDP_packet.values():
            if len(dp) == 0:
                self.have_empty = True
        if self.have_empty == False:
            self.filter_switch_for_UDP_packet()
    
     ##############################################################
    # Group Stats Reply handling
    #
    @set_ev_cls(ofp_event.EventOFPGroupStatsReply, MAIN_DISPATCHER)
    def _groups_stats_reply_handler(self, ev):
        self.have_empty = False
        groups = ev.msg.body
        self.logger.info('datapath         '
                        'ref-count'
                         ' group-id packets  bytes')
        self.logger.info('---------------- '
                        '--------  '
                         '-------- -------- --------')

        for stat in groups:
            self.logger.info('%016x %8d %8x %8d %8d',ev.msg.datapath.id,
                                    stat.ref_count ,stat.group_id,stat.packet_count,stat.byte_count)
            if ev.msg.datapath.id in self.UDP_packet.keys():
                if ev.msg.datapath.id in self.link_connection_switch.keys():
                    for switch in self.link_connection_switch[ev.msg.datapath.id]:
                            self.UDP_packet[ ev.msg.datapath.id ][self.link_connection_switch[ev.msg.datapath.id][switch][0]]= stat.packet_count
        n_switches = self.num_switches()
        for dp in self.UDP_packet.values():
            if len(dp) == 0:
                self.have_empty = True
        if self.have_empty == False:
            self.filter_switch_for_UDP_packet()
    ####################################################################################################################
    ### Change the switch connection from dst_port in self.UDP_packet()
    #
    def filter_switch_for_UDP_packet(self):
        print("")
        for dpid in self.UDP_packet.keys():
            self.loss_packet.setdefault(dpid,{})
            if dpid in self.Topology_db.keys():
                for next_switch in self.Topology_db[dpid]:
                    for port in self.UDP_packet[dpid]:
                        if port == self.Topology_db[dpid][next_switch][0]:
                            save = self.UDP_packet[dpid][port]
                            self.loss_packet[dpid][next_switch]=save
                            break

        self.estimate_loss()
    ####################################################################################################################
    ### Estimate Link Loss rate
    #
    def estimate_loss(self):
        self.estimate_link_loss = copy.deepcopy(self.link_connection_switch)
        print("Packet Loss {}".format(self.loss_packet))
        for dpid in self.link_connection_switch.keys():
            for next_switch in self.link_connection_switch[dpid]:
                if dpid in self.loss_packet.keys():
                    if len(self.loss_packet[dpid]) == 1:
                        for dp_id in self.loss_packet.keys():
                            if dp_id == next_switch:
                                for target_switch in self.loss_packet[dp_id]:
                                    if target_switch != dpid:
                                        
                                        self.estimate_link_loss[dpid][next_switch]= round(float(float(abs(self.loss_packet[dpid][next_switch]-self.loss_packet[dp_id].values()[0]))/float(self.loss_packet[dpid][next_switch])),4)
                                    else:
                                        self.estimate_link_loss[dpid][next_switch]= round(float(float(abs(self.loss_packet[dpid][next_switch]-self.loss_packet[dp_id][target_switch]))/float(self.loss_packet[dpid][next_switch])),4)
                    else:
                        for dp_id in self.loss_packet.keys():
                            if all(self.loss_packet[dp_id].values()):
                                if dp_id == next_switch:
                                   for target_switch in self.loss_packet[dp_id]:
                                        if target_switch != dpid:
                                            self.estimate_link_loss[dpid][next_switch] = round(float(float(abs(self.loss_packet[dpid][next_switch]-self.loss_packet[dp_id].values()[0]))/float(self.loss_packet[dpid][next_switch])),4)
                                        else:
                                            self.estimate_link_loss[dpid][next_switch]= round(float(float(abs(self.loss_packet[dpid][next_switch]-self.loss_packet[dp_id][target_switch]))/float(self.loss_packet[dpid][next_switch] )),4)
                            else:
                                if dp_id == next_switch:
                                    for target_switch in self.loss_packet[dp_id]: 
                                        if target_switch == dpid:
                                            self.estimate_link_loss[dpid][next_switch]= round(float(float(abs(self.loss_packet[dpid][next_switch]-self.loss_packet[dp_id][target_switch]))/float(self.loss_packet[dpid][next_switch])),4)
        print("\n Estimate Link Loss: {}".format(self.estimate_link_loss))
    ##############################################################
    def Get_dst_dpid(self, mac):
        for dpid in self.ARP_table.keys():
            if mac in self.ARP_table[dpid].keys():
                return dpid
        return
    

    ##############################################################
    # Port status changed
    # If port status is MOD and DOWN 
    #    -> Exercise 1.2: Remmove MAC from MAC table 
    #    -> Exercise 1.3: Remove Flow table
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)    
    def port_changed(self, ev):
        msg = ev.msg
        dp  = msg.datapath
        ofp = dp.ofproto

        reason  = msg.reason
        desc    = msg.desc
        port_no = desc.port_no

        if reason == ofp.OFPPR_ADD:
            reason_st = 'ADD'
        elif reason == ofp.OFPPR_DELETE:
            reason_st = 'DELETE'
        elif reason == ofp.OFPPR_MODIFY:
            reason_st = 'MODIFY'
        else:
            reason_st = 'UNKNOWN'
        
        if desc.state == ofp.OFPPS_LINK_DOWN:
            state = 'DOWN'
        elif desc.state == ofp.OFPPS_BLOCKED:
            state = 'BLOCKED'
        elif desc.state == ofp.OFPPS_LIVE:
            state = 'LIVE'
        else:
            state = 'UNKNOWN'

        print("\nTopology is Changed (Port is Changed at datapath ID of {}) - Reason={} - Port No={}, State={} -- Log at: {}"
            .format(dp.id,reason_st,port_no, state, datetime.datetime.now()))
        
        #Find the removed MAC address
        if reason_st == 'DELETE' or state == 'DOWN' or state == 'BLOCKED':
            if dp.id in self.MAC_table.keys():
                _have_mac = False
                for _mac in self.MAC_table[dp.id].keys():
                    if self.MAC_table[dp.id][_mac] == port_no:
                        _have_mac = True
                        break
                
                if (_have_mac):
                    #Remove invalid entries from the flow table of OFSs
                    print("   - Remove invalid entries from the flow table")
                    for _dp in self.datapaths.values():
                        _match   = _dp.ofproto_parser.OFPMatch(eth_dst=_mac)
                        self.flow_rem(_dp, _match)
                    
                    #Remove invalided entries from tables (MAC, ARP)
                    print("   - Remove invalid entries of {} from the MAC/ARP table".format(_mac))
                    self.MAC_table[dp.id].pop(_mac)
                    self.ARP_table[dp.id].pop(_mac)

        #Network is changed => Call update topology
        if reason_st == 'ADD':
            if(self.network_changed_thread != None):
                hub.kill(self.network_changed_thread)
            self.network_changed_thread = hub.spawn_after(1,self.network_changed)

        if reason_st == 'DELETE':
            if dp.id in self.Topology_db.keys():
                for _dpid_dst in self.Topology_db[dp.id].keys():
                    if port_no == self.Topology_db[dp.id][_dpid_dst][0]:
                        #This port connect to another OFS => Network changed
                        if(self.network_changed_thread != None):
                            hub.kill(self.network_changed_thread)
                        self.network_changed_thread = hub.spawn_after(1,self.network_changed)
                        break
   


    ##############################################################
    # Flow add/remove functions
    #
    def flow_add(self, dp, idle_timeout, priority, match, instructions):
        ofp        = dp.ofproto
        ofp_parser = dp.ofproto_parser
        mod        = ofp_parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_ADD, 
                                           idle_timeout=idle_timeout, priority=priority, 
                                           
                                           match=match, instructions=instructions)
        if priority==0:
            in_port = "Any"
            eth_dst = "Any"
        else:
            in_port = match["in_port"]
            eth_dst = match["eth_dst"]
        #
        print("      + FlowMod (ADD) of Datapath ID={}, Match: (Dst. MAC={}, PortIn={}), Action: (PortOut={})".format(
            dp.id, eth_dst, in_port, instructions[0].actions[0].port))

        dp.send_msg(mod)

    def flow_rem(self, dp, match):
        ofp        = dp.ofproto
        ofp_parser = dp.ofproto_parser
        mod        = ofp_parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE, out_port=ofp.OFPP_ANY, out_group=ofp.OFPP_ANY, match=match)
        print("      + FlowMod (REMOVE) of Datapath ID={}, Match: (Dst. MAC={})".format(dp.id, match["eth_dst"]))
        dp.send_msg(mod)


    ##############################################################
    # Network Changed:
    #   1. Switch is added or removed/unavailable
    #   2. Port status is changed (UP/DOWN)
    #

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        self.logger.info('datapath         '
                         ' port-in   bytes')
        self.logger.info('---------------- '
                        
                         '-------- --------')
        for p in ev.msg.body:
            self.logger.info('%016x  %8x %8d ',ev.msg.datapath.id,
                                    p.port_no,p.curr_speed)
    #######################################
    # 1a. Switch is added
    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        print("\nSwitch entering (Datapath ID = {}) --------------- Log at: {}".format(ev.switch.dp.id, datetime.datetime.now()))
        if(self.network_changed_thread != None):
            hub.kill(self.network_changed_thread)
        self.network_changed_thread = hub.spawn_after(1,self.network_changed)
        req = ev.switch.dp.ofproto_parser.OFPPortDescStatsRequest(ev.switch.dp)
        ev.switch.dp.send_msg(req)

    #######################################
    # 1b. Switch is removed/unavailable
    @set_ev_cls(event.EventSwitchLeave)
    def handler_switch_leave(self, ev):
        print("\nSwitch leaving (Datapath ID = {}) --------------- Log at: {}".format(ev.switch.dp.id, datetime.datetime.now()))
        if(self.network_changed_thread != None):
            hub.kill(self.network_changed_thread)
        self.network_changed_thread = hub.spawn_after(1,self.network_changed)

    #######################################
    # Update the topology
    #   * No care end hosts
    # 
    def network_changed(self):
        print("\nNetwork is changed------------------------------- Log at: {}".format(datetime.datetime.now()))
        self.topo_raw_links = get_link(self, None)
        self.topo_raw_switches = get_switch(self,None)
        for _dpid in self.MAC_table.keys():
            for _mac in self.MAC_table[_dpid].keys():
                for _dp in self.datapaths.values():
                    _match   = _dp.ofproto_parser.OFPMatch(eth_dst=_mac)
                    self.flow_rem(_dp, _match)

        self.BuildTopology()

    def BuildTopology(self):
        self.Topology_db.clear()

        for l in self.topo_raw_links:
            _dpid_src = l.src.dpid
            _dpid_dst = l.dst.dpid
            _port_src = l.src.port_no
            _port_dst = l.dst.port_no
            
            self.Topology_db.setdefault(_dpid_src,{})
            self.Topology_db[_dpid_src][_dpid_dst] = [_port_src,_port_dst]
        print("   - Topology Database: {}".format(self.Topology_db))

        for l in self.topo_raw_switches:
            dpid_src=l.dp.id
            self.switch_port_connect=[]
            for m in range(len(l.ports)):
                
                self.port_connect = l.ports[m].port_no
                m=m+1
                self.switch_port_connect.append(self.port_connect)
                
            self.port_switch[dpid_src]=self.switch_port_connect   
        print("")
        print("   - All switch-port Database: {}".format(self.port_switch))
        print("")
        self.filter_link_connection_between_switch()
        print("")
        self.filter_link_connection_between_switch_for_drop()

    """
    For example You have the Topology Database like this:
    - Topology Database:   {1: {2: [2, 2]}, 
                            2: {1: [2, 2], 3: [3, 2],5: [4, 2]}, 
                            3: {2: [2, 3], 4: [3, 2], 6: [4, 3]}, 
                            4: {3: [2, 3]}, 
                            5: {2: [2, 4], 6: [3, 2]}, 
                            6: {3: [3, 4], 5: [2, 3]}}
    What you need now the filter of link connection between two switches
        Something like this :  {1: {2:[2,2]},
                                2: {3: [3, 2],5: [4, 2]},
                                3: {4: [3, 2], 6: [4, 3]},
                                5: {6: [3, 2]}
    The reason for this action because you need to use the GroupMod packet 
    to insert the ports into multicast port so that the UDP packet will be cloned
    when OpenFlow Switches see that entries. This is important since you can not use 
    the FLood Command to measure the link loss because the loop if your topology is not linear
    """
    ##############################################################
    # Filter the connection between switch to find the link loss
    # 

    def filter_link_connection_between_switch(self):
        for l in range(len(self.Topology_db.keys())):
            self.link_connection_switch.setdefault(self.Topology_db.keys()[l],{})
            for i in range(l+1,len(self.Topology_db.keys())):
                for dp_id in self.Topology_db.values()[i].keys():
                    for dpid in self.Topology_db.values()[l].keys():
                        if dp_id ==  self.Topology_db.keys()[l]:
                            if dpid == self.Topology_db.keys()[i]:
                                self.link_connection_switch[dp_id][dpid]=0
        ##################################################################################
        for key,values in list(self.link_connection_switch.items()):
            if len(values) == 0:
                del self.link_connection_switch[key]
        ###################################################################################
        for dp in self.Topology_db.keys():
            if dp in self.link_connection_switch.keys():
                for key in self.link_connection_switch[dp].keys():
                    if key in self.Topology_db.keys():
                            self.link_connection_switch[dp][key] = self.Topology_db[dp][key]  
        print("   - All switch-switch link filter: {}".format(self.link_connection_switch))               
    ##############################################################
    # Filter the connection between switch to apply the drop rule
    # 
    def filter_link_connection_between_switch_for_drop(self):
        for dpid in self.Topology_db.keys():
            if dpid not in self.link_connection_switch.keys():
                self.switch_drop.setdefault(dpid,{})
                self.switch_drop[dpid]=self.Topology_db[dpid]
        print("   - All destination switch: {}".format(self.switch_drop))
    ##############################################################
    # Exercise 2.1
    # Find the best route using DFS (Depth First Search) algorithm
    # (source datapath, destination datapath)
    def FindRoute(self,dpid_src,dpid_dst):
        # Case 1: Destination is on the same Switch:
        if dpid_src == dpid_dst:
            return [dpid_src]
        
        # Case 2: Destination is on another Switch:
        paths = []
        stack = [(dpid_src, [dpid_src])]
        while stack:
            (node, path) = stack.pop()
            for next_node in set(self.Topology_db[node].keys()) - set(path):
                if next_node == dpid_dst:
                    paths.append(path + [next_node])
                else:
                    stack.append((next_node, path + [next_node]))

        # The best route is the route having the 'minimum hop count'
        shortest_path_hops = 1000
        for path in paths:
            if len(path) < shortest_path_hops:
                shortest_path_hops = len(path)
                shortest_path = path
        
        print("   - Routing request from {} to {}. Result: {}  (Datapath ID)".format(dpid_src, dpid_dst, shortest_path))

        return shortest_path

    #Find the exit interface
    def Get_port_out (self,dpid_src,dpid_dst,mac):
        # Destination is on the same Switch:
        if dpid_src == dpid_dst:
            return self.MAC_table[dpid_src][mac]

        return self.Topology_db[dpid_src][dpid_dst][0]

    #####################################################################################
    ### Send the number of switch in topology
    #
    def num_switches(self):
        return len(self.topo_raw_switches)
