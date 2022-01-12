#!/usr/bin/python
# -*- coding: utf-8 -*-

# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types as ether
from ryu.lib.packet import ether_types
from ryu.lib import pcaplib
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import ipv4
from config import *
import time
import datetime
import pytz

class SimpleSwitch13(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        log('[+] TelemWatch-NG Started')
        self.pcap_pen = pcaplib.Writer(file_obj=open(PCAP, 'wb'))
        self.STARTUP = True

    def drop_flow_tcp(self, datapath, tcp_port):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(ip_proto=6, tcp_src=tcp_port,
                                eth_type=ether.ETH_TYPE_IP)

        mod = parser.OFPFlowMod(datapath=datapath, table_id=0,
                                priority=5000, match=match,
                                instructions=[])
        datapath.send_msg(mod)

    def reset_pkt(self,eth_pkt, ipv4_pkt, tcp_pkt, datapath,ofproto,parser,in_port):
            tcp_hd = tcp.tcp(ack=tcp_pkt.seq + 1, src_port=tcp_pkt.dst_port, dst_port=tcp_pkt.src_port,bits = (tcp.TCP_RST))
            ip_hd = ipv4.ipv4(dst=ipv4_pkt.src, src=ipv4_pkt.dst, proto=ipv4_pkt.proto)
            ether_hd = ethernet.ethernet(ethertype=ether.ETH_TYPE_IP, dst=eth_pkt.src, src=eth_pkt.dst)
            tcp_rst_ack = packet.Packet()
            tcp_rst_ack.add_protocol(ether_hd)
            tcp_rst_ack.add_protocol(ip_hd)
            tcp_rst_ack.add_protocol(tcp_hd)
            tcp_rst_ack.serialize()
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, ofproto.OFPP_CONTROLLER, actions, tcp_rst_ack.data)
            datapath.send_msg(out)


    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        buffer_id=None,
        ):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = \
            [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=0,
                                    priority=priority, match=match,
                                    instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        log('[+] Switch Connected.')
        datapath = ev.msg.datapath
	f = open('datapath.raw','wb')
	f.write(str(datapath))
	f.close()
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                   ofproto.OFPCML_NO_BUFFER)]
        priority = 1000
	
        self.add_flow(datapath, priority, match, actions)
        if self.STARTUP:
            info('[*] TelemWatch-NG Activated')
            self.STARTUP = False

        else:
            warn('[*] Switch Reconnected.')
        req = parser.OFPSetConfig(datapath,
                                  ofproto_v1_3.OFPC_FRAG_NORMAL, 1500)
        datapath.send_msg(req)


    def upretty_print_pkt(self,device,i,pkt_udp):
	if i.src not in LOGLIST:
		return
        t = str(datetime.datetime.now())
        log('['+str(device)+']\t\t['+t+']\t'+str(pkt_udp.src_port)+"->"+str(i.dst)+" : "+str(pkt_udp.dst_port)+"//"+str(i.total_length))
    
    def pretty_print_pkt(self,device,i,pkt_tcp):
	if i.src not in LOGLIST:
		return
        t = str(datetime.datetime.now(pytz.timezone('US/Eastern')))
	log('['+str(device)+']\t\t['+t+']\t'+str(pkt_tcp.src_port)+"->"+str(i.dst)+" : "+str(pkt_tcp.dst_port)+"//"+str(i.total_length)+"//"+str(pkt_tcp.bits))

    def warning_msg(self,device,i,pkt_tcp,m):
	if i.src not in LOGLIST:
		return
        t = str(datetime.datetime.now())
        warn('['+str(device)+']\t['+t+']\t[Action: '+str(m)+']\t'+str(pkt_tcp.src_port)+"->"+str(i.dst)+" : "+str(pkt_tcp.dst_port)+"//"+str(i.total_length))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
	p = packet.Packet()

        if pkt_tcp:
            e = pkt.get_protocol(ethernet.ethernet)
            i = pkt.get_protocol(ipv4.ipv4)

	    if (i.src==NEST):
		self.pretty_print_pkt('NEST-PROTECT',i,pkt_tcp)

	    if (i.src==MYQ):
		self.pretty_print_pkt('MYQ-GARAGE',i,pkt_tcp)
		if (i.total_length==125):
			self.warning_msg('MY-Q',i,pkt_tcp,'[!] Dropping MYQ MQQT Action')
			return
	
	    if (i.src==HUE):
		self.pretty_print_pkt('HUE-HUB',i,pkt_tcp)
		if (i.total_length > 500):
			self.warning_msg('HUE-HUB',i,pkt_tcp,'[!] Dropping Hue Action')
			return

	    elif (i.src==LYNX):
		self.pretty_print_pkt('LYNX-CAMERA',i,pkt_tcp)
		if ((pkt_tcp.dst_port==443)):
			self.warning_msg('LYNX-CAMERA',i,pkt_tcp,'[!] Dropping Motion Notification on SSL')
			return

            elif (i.src==GEENIE):
		self.pretty_print_pkt('GEENIE-CAMERA',i,pkt_tcp)
		if pkt_tcp.dst_port==1883 and "smart/device/out" in str(pkt.protocols[-1]):
			self.warning_msg('GEENIE-CAMERA',i,pkt_tcp,'[!] Dropping MQQT Telemetry')
			return
			
	    elif (i.src==IRIS):
		self.pretty_print_pkt('IRIS-HUB',i,pkt_tcp)
		if (pkt_tcp.bits==24 and pkt_tcp.dst_port==443 and i.total_length > 250):
			self.warning_msg('IRIS-HUB',i,pkt_tcp,'[!] Dropping IRIS Telemetry Data (PSH|ACK)')
			return

            elif (i.src==SMARTTHINGS):
		self.pretty_print_pkt('SMART-THINGS-HUB',i,pkt_tcp)
		if i.total_length > 359:
			self.warning_msg('SMART-THINGS-HUB',i,pkt_tcp,'[!] Dropping Smart Things Telemetry (PKT > 300)')
			return
				    
       	    elif (i.src==IVIEW or i.src==WSTEIN or i.src==TUYA):
		self.pretty_print_pkt('TUYA-MOTIONSENSE',i,pkt_tcp)
             	if "out" in str(pkt.protocols[-1]):
			self.warning_msg('TUYA Motion Sense',i,pkt_tcp,'[!] Dropping Motion Sense Alert (MQTT)')
			return

            elif i.src==DLINK:
		self.pretty_print_pkt('DLINK-MOTION',i,pkt_tcp)
		if (pkt_tcp.dst_port==443 and i.total_length > 475): #pkt_tcp.bits==24):
			self.warning_msg('DLINK-MOTION',i,pkt_tcp,'[!] Dropping Dlink Motion  (SSL > 475)')
			return

	    elif i.src==DLINK_CAM:
		self.pretty_print_pkt('DLINK-CAMERA',i,pkt_tcp)
		if (pkt_tcp.dst_port==443 and i.total_length > 600 and pkt_tcp.bits==24):
			self.warning_msg('DLINK-CAMERA',i,pkt_tcp,'[!] Dropping Dlink Camera (>400,SSL,P/A)')
			return

	    elif i.src==AXEL_CAM:
		self.pretty_print_pkt('AXEL-CAMERA',i,pkt_tcp)
		if (i.total_length > 600 and pkt_tcp.dst_port==443 and pkt_tcp.bits==24):
			self.warning_msg('AXEL-CAMERA',i,pkt_tcp,'[!] Dropping AXEL Camera (>600,SSL,P/A)')
			return

	    elif i.src==MERCURY:
		self.pretty_print_pkt('MERCURY-CAMERA',i,pkt_tcp)
		if pkt_tcp.dst_port==1883 and "smart/device/out" in str(pkt.protocols[-1]):
			self.warning_msg('MERKURY-CAMERA',i,pkt_tcp,'[!] Dropping MQQT Telemetry')
			return

            elif i.src==WYZE:
		self.pretty_print_pkt('WYZE-CAMERA',i,pkt_tcp)
	    	if pkt_tcp.dst_port==8443:
			self.warning_msg('WYZE-CAM',i,pkt_tcp,'[!] Dropping Wyze Cam 8443 Telemetry')
	    		return

	    elif i.src==WYZEV2:
		self.pretty_print_pkt('WYZE-V2-CAMERA',i,pkt_tcp)
		if pkt_tcp.dst_port==8883:
			self.warning_msg('WYZE-V2',i,pkt_tcp,'[X] Dropping Wyze CAm 8883 Telemetry')
			return
		elif pkt_tcp.dst_port==8443:
			self.warning_msg('WYZE-V2',i,pkt_tcp,'[X] Dropping Wyze Cam 8443 Telemetry')
			return

	    elif i.src==WEMO:
		self.pretty_print_pkt('WEMO-MOTION',i,pkt_tcp)
		if (pkt_tcp.dst_port==8443 or pkt_tcp.dst_port==3478):
			self.warning_msg('WEMO-MOTION',i,pkt_tcp,'[!] Dropping WeMo Motion (8443 & 3478)')
			return
	
	    elif i.src==CANARY:
		self.pretty_print_pkt('CANARY-CAMERA',i,pkt_tcp)
		if ((pkt_tcp.dst_port==443) and i.total_length==1500):
			self.warning_msg('CANARY-CAMERA',i,pkt_tcp,'[!] Dropping Canary Telemetry')
			return

	    elif i.src==RING:
		self.pretty_print_pkt('RING-PRO',i,pkt_tcp)
		if pkt_tcp.dst_port==15063 or (pkt_tcp.dst_port==9999 and (i.total_length!=183 and i.total_length!=52)): 
			self.warning_msg('RING-PRO',i,pkt_tcp,'[!] Dropping Ring Notification')
			return

	    elif i.src==RING2:
                self.pretty_print_pkt('RING-STD',i,pkt_tcp)
		if pkt_tcp.dst_port==80:
                        self.warning_msg('RING-STD',i,pkt_tcp,'[!] Dropping Ring Notification (port 80)')
                        return
		
	    self.pcap_pen.write_pkt(msg.data)
        
	if pkt_udp:
	    i = pkt.get_protocol(ipv4.ipv4)
            if i:
		if i.src in LOGLIST:
		    self.upretty_print_pkt('(UDP:'+str(i.src)+')',i,pkt_udp)

	    	self.pcap_pen.write_pkt(msg.data)
	eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions,
                                  data=data)
        datapath.send_msg(out)
