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

import java.util.HashMap;
import java.util.Map;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;

import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;

import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.ARP;

import org.onosproject.net.PortNumber;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.flow.FlowRuleService;

import org.onlab.packet.IpAddress;
import java.nio.ByteBuffer;

import org.onosproject.net.device.DeviceService;

/**
 * Proxy ARP ONOS application component.
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
    protected DeviceService deviceService;

    private ProxyArpProcessor processor = new ProxyArpProcessor();
    private ApplicationId appId;
    private Map<IpAddress, MacAddress> arpTable = new HashMap<>();

    @Activate
    protected void activate() {

        // register your app
        appId = coreService.registerApplication("nycu.winlab.proxyarp");

        // add a packet processor to packetService
        packetService.addProcessor(processor, PacketProcessor.director(2));

        // install a flowrule for packet-in
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

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
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Stopped");
    }

    private class ProxyArpProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // stop processing if the packet has been handled, since we
            // can't do any more to it.
            if (context.isHandled()) {
                return;
            }
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null || !(ethPkt.getPayload() instanceof ARP)) {
                return;
            }

            ARP arpPkt = (ARP) ethPkt.getPayload();
            DeviceId recDevId = pkt.receivedFrom().deviceId();
            PortNumber recPort = pkt.receivedFrom().port();
            IpAddress srcIP = IpAddress.valueOf(IpAddress.Version.INET, arpPkt.getSenderProtocolAddress());
            IpAddress dstIP = IpAddress.valueOf(IpAddress.Version.INET, arpPkt.getTargetProtocolAddress());
            MacAddress srcMac = MacAddress.valueOf(arpPkt.getSenderHardwareAddress());

            if (arpPkt.getOpCode() == ARP.OP_REQUEST) { // ARP request
                // update the ARP table
                arpTable.put(srcIP, srcMac);
                MacAddress dstMac = arpTable.get(dstIP);
                // check if the destination IP is in the table
                if (dstMac != null) { // table hit -> send ARP reply
                    log.info("TABLE HIT. Requested MAC = {}", dstMac);
                    reply(ethPkt, recDevId, recPort, srcIP, dstMac);
                } else { // table miss -> flood the ARP request
                    log.info("TABLE MISS. Send request to edge ports");
                    flood(pkt, recDevId, recPort);
                }
            } else if (arpPkt.getOpCode() == ARP.OP_REPLY) { // ARP reply
                log.info("RECV REPLY. Requested MAC = {}", srcMac);
                // update the ARP table
                arpTable.put(srcIP, srcMac);
                context.block();
            }
        }

        private void reply(Ethernet ethPkt, DeviceId recDevId, PortNumber recPort, IpAddress dstIP, MacAddress dstMac) {
            Ethernet ethReply = ARP.buildArpReply(dstIP.getIp4Address(), dstMac, ethPkt);
            TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(recPort).build();
            OutboundPacket packet = new DefaultOutboundPacket(recDevId, treatment,
                    ByteBuffer.wrap(ethReply.serialize()));
            packetService.emit(packet);
        }

        private void flood(InboundPacket pkt, DeviceId recDevId, PortNumber recPort) {
            for (Port port : deviceService.getPorts(recDevId)) {
                if (!port.number().equals(recPort)) {
                    TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(port.number()).build();
                    OutboundPacket packet = new DefaultOutboundPacket(recDevId, treatment, pkt.unparsed());
                    packetService.emit(packet);
                }
            }
        }
    }
}
