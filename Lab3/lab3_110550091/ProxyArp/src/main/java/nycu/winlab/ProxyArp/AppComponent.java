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
package nycu.winlab.proxyarp;

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

import org.onosproject.net.flow.FlowRuleService;

import org.onlab.packet.IpAddress;
import java.nio.ByteBuffer;

import org.onosproject.net.device.DeviceService;
import org.onosproject.net.Port;

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
            // Stop processing if the packet has been handled, since we
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
            DeviceId deviceId = pkt.receivedFrom().deviceId();
            PortNumber inPort = pkt.receivedFrom().port();

            IpAddress sourceIp = IpAddress.valueOf(IpAddress.Version.INET, arpPkt.getSenderProtocolAddress());
            IpAddress targetIp = IpAddress.valueOf(IpAddress.Version.INET, arpPkt.getTargetProtocolAddress());
            MacAddress sourceMac = MacAddress.valueOf(arpPkt.getSenderHardwareAddress());
            MacAddress targetMac = MacAddress.valueOf(arpPkt.getTargetHardwareAddress());

            if (arpPkt.getOpCode() == ARP.OP_REQUEST) {
                // put the mapping of source ip and source mac into arp table
                if (arpTable.get(sourceIp) == null) {
                    arpTable.put(sourceIp, sourceMac);
                }
                // check if the target ip is in the arp table
                if (arpTable.get(targetIp) != null) {
                    // send arp reply
                    log.info("TABLE HIT. Requested MAC = {}", arpTable.get(targetIp));
                    sendArpReply(context, sourceIp, targetIp, arpTable.get(targetIp), sourceMac);
                } else {
                    // forward the arp request to other ports
                    log.info("TABLE MISS. Send request to edge ports");
                    flood(context);
                }
            } else if (arpPkt.getOpCode() == ARP.OP_REPLY) {
                // Update ARP table
                log.info("RECV REPLY. Requested MAC = {}", sourceMac);
                arpTable.put(sourceIp, sourceMac);

                context.block();
            }
        }

        private void sendArpReply(
            PacketContext context,
            IpAddress senderIp,
            IpAddress targetIp,
            MacAddress senderMac,
            MacAddress targetMac) {
            Ethernet ethReply = ARP.buildArpReply(
                targetIp.getIp4Address(),
                senderMac,
                context.inPacket().parsed());
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(context.inPacket().receivedFrom().port())
                    .build();
            OutboundPacket packet = new DefaultOutboundPacket(
                    context.inPacket().receivedFrom().deviceId(),
                    treatment, ByteBuffer.wrap(ethReply.serialize()));
            packetService.emit(packet);
        }

        private void flood(PacketContext context) {
            DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
            PortNumber inPort = context.inPacket().receivedFrom().port();

            for (Port port : deviceService.getPorts(deviceId)) {
                if (!port.number().equals(inPort)) {
                    TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                            .setOutput(port.number())
                            .build();
                    OutboundPacket packet = new DefaultOutboundPacket(
                            deviceId,
                            treatment,
                            context.inPacket().unparsed());
                    packetService.emit(packet);
                }
            }
        }
    }
}
