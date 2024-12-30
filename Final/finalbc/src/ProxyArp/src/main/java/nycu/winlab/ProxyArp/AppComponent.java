/*
 * Copyright 2024-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nycu.winlab.ProxyArp;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.edge.EdgePortService;

import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.ARP;
import org.onlab.packet.MacAddress;
import org.onlab.packet.ndp.NeighborAdvertisement;
import org.onlab.packet.ndp.NeighborSolicitation;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import org.onosproject.net.PortNumber;
import org.onosproject.net.DeviceId;
import org.onosproject.net.ConnectPoint;

import org.onosproject.net.flow.FlowRuleService;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgeService;

    private ProxyArpProcessor processor = new ProxyArpProcessor();
    private ApplicationId appId;
    private Map<Ip4Address, MacAddress> ipv4ProxyArpTable = new HashMap<>();
    private Map<Ip6Address, MacAddress> ipv6ProxyArpTable = new HashMap<>();
    private Map<MacAddress, ConnectPoint> connectPointTable = new HashMap<>();

    @Activate
    protected void activate() {

        // register your app
        appId = coreService.registerApplication("nycu.winlab.ProxyArp");

        // add a packet processor to packetService
        packetService.addProcessor(processor, PacketProcessor.director(3));

        // install a flowrule for packet-in
        TrafficSelector.Builder ipv4Selector = DefaultTrafficSelector.builder();
        ipv4Selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(ipv4Selector.build(), PacketPriority.REACTIVE, appId);

        TrafficSelector.Builder ipv6Selector = DefaultTrafficSelector.builder();
        ipv6Selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.requestPackets(ipv6Selector.build(), PacketPriority.REACTIVE, appId);
       
        ipv4ProxyArpTable.put(Ip4Address.valueOf( IPv4.toIPv4AddressBytes("172.16.8.1")), MacAddress.valueOf("00:00:00:00:00:02"));
        ipv6ProxyArpTable.put(Ip6Address.valueOf("2a0b:4e07:c4:8::1"), MacAddress.valueOf("00:00:00:00:00:02"));

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {

        // remove flowrule installed by your app
        flowRuleService.removeFlowRulesById(appId);

        // remove your packet processor
        packetService.removeProcessor(processor);
        processor = null;

        // remove flowrule you installed for packet-in
        TrafficSelector.Builder ipv4Selector = DefaultTrafficSelector.builder();
        ipv4Selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(ipv4Selector.build(), PacketPriority.REACTIVE, appId);

        TrafficSelector.Builder ipv6Selector = DefaultTrafficSelector.builder();
        ipv6Selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(ipv6Selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Stopped");
    }

    private class ProxyArpProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            if (context.isHandled()) {
                return;
            }
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            if (ethPkt.getEtherType() != Ethernet.TYPE_ARP && ethPkt.getEtherType() != Ethernet.TYPE_IPV6) {
                return;
            }

            DeviceId recDevId = pkt.receivedFrom().deviceId();
            PortNumber recPort = pkt.receivedFrom().port();
            MacAddress srcMac = ethPkt.getSourceMAC();
            // MacAddress dstMac = ethPkt.getDestinationMAC();


            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                ARP arpPayload = (ARP) ethPkt.getPayload();
                Ip4Address srcIp4Address = Ip4Address.valueOf(arpPayload.getSenderProtocolAddress());
                Ip4Address dstIp4Address = Ip4Address.valueOf(arpPayload.getTargetProtocolAddress());

                if (arpPayload.getOpCode() == ARP.OP_REPLY) {
                    // the mapping of pkt's src mac and receivedfrom port wasn't store in the table of the rec device
                    log.info("RECV REPLY. Requested MAC = {}", srcMac);
                    ipv4ProxyArpTable.put(srcIp4Address, srcMac);
                    connectPointTable.put(srcMac, pkt.receivedFrom());
                } else if (ipv4ProxyArpTable.get(srcIp4Address) == null) {
                    ipv4ProxyArpTable.put(srcIp4Address, srcMac);
                    connectPointTable.put(srcMac, pkt.receivedFrom());
                } else if (arpPayload.getOpCode() == ARP.OP_REQUEST) {
                    if (ipv4ProxyArpTable.get(dstIp4Address) == null) {
                        // the mapping of dst mac and forwarding port wasn't store in the table of the rec device
                        log.info("TABLE MISS. Send request to edge ports");
                        // flood arp request except the receivedfrom port
                        for (ConnectPoint cp : edgeService.getEdgePoints()) {
                            if (recDevId != cp.deviceId() || recPort != cp.port()) {
                                packetOut(cp.deviceId(), cp.port(), ByteBuffer.wrap(ethPkt.serialize()));
                            }
                        }
                    } else {
                        // there is a entry store the mapping of dst mac and forwarding port
                        // send arp reply
                        MacAddress targetMac = ipv4ProxyArpTable.get(dstIp4Address);
                        Ethernet arpPacket = ARP.buildArpReply(dstIp4Address, targetMac, ethPkt);
                        log.info("TABLE HIT. Requested MAC = {}", targetMac);
                        packetOut(recDevId, recPort, ByteBuffer.wrap(arpPacket.serialize()));
                    }   
                }
            } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6Payload = (IPv6) ethPkt.getPayload();
                if (ipv6Payload.getNextHeader() == IPv6.PROTOCOL_ICMP6) {
                    Ip6Address srcIp6Address = Ip6Address.valueOf(ipv6Payload.getSourceAddress());
                    if (ipv6ProxyArpTable.get(srcIp6Address) == null) {
                        ipv6ProxyArpTable.put(srcIp6Address, srcMac);
                    } 
                    ICMP6 icmp6Payload = (ICMP6) ipv6Payload.getPayload();
                    

                    if (icmp6Payload.getIcmpType() == ICMP6.NEIGHBOR_ADVERTISEMENT) {
                        NeighborAdvertisement ndpPacket = (NeighborAdvertisement) icmp6Payload.getPayload();
                   
                        Ip6Address TargetIp6Address = Ip6Address.valueOf(ndpPacket.getTargetAddress());
                        MacAddress TargetMacAddress = srcMac;
                        log.info("target ipv6 address = {}", TargetIp6Address);
                        ipv6ProxyArpTable.put(TargetIp6Address, TargetMacAddress);

                    } else if (icmp6Payload.getIcmpType() == ICMP6.NEIGHBOR_SOLICITATION) {
                        NeighborSolicitation ndpPacket = (NeighborSolicitation) icmp6Payload.getPayload();
                   
                        Ip6Address TargetIp6Address = Ip6Address.valueOf(ndpPacket.getTargetAddress());
                        if (ipv6ProxyArpTable.get(TargetIp6Address) == null) {
                            // flood neighbor solicitation
                            for (ConnectPoint cp : edgeService.getEdgePoints()) {
                                if (recDevId != cp.deviceId() || recPort != cp.port()) {
                                    packetOut(cp.deviceId(), cp.port(), ByteBuffer.wrap(ethPkt.serialize()));
                                }
                            }
                        } else {
                            // send proxy neighbor advertisement packet
                            MacAddress targetMac = ipv6ProxyArpTable.get(TargetIp6Address);
                            Ethernet icmp6Packet = NeighborAdvertisement.buildNdpAdv(TargetIp6Address, targetMac, ethPkt);
                            IPv6 ipv6Reply = (IPv6) icmp6Packet.getPayload();
                            ipv6Reply.setHopLimit((byte) 255);
                            icmp6Packet.setPayload(ipv6Reply);
                            packetOut(recDevId, recPort, ByteBuffer.wrap(icmp6Packet.serialize()));
                            log.info("TABLE6 HIT. Requested MAC = {}", targetMac);
                        }
                    }
                }
            }
            
        }
    }

    private void packetOut(DeviceId targetDeviceId, PortNumber portNumber, ByteBuffer pktData) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
        .setOutput(portNumber).build();
        OutboundPacket outboundPacket = new DefaultOutboundPacket(targetDeviceId, treatment, pktData);
        packetService.emit(outboundPacket);
    }
}