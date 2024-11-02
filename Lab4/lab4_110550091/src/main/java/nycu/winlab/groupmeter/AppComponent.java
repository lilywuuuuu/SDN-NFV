package nycu.winlab.groupmeter;

import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;

import org.onlab.packet.ARP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.GroupId;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criteria;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;

import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.FilteredConnectPoint;
import org.onosproject.net.PortNumber;

import org.onosproject.net.group.DefaultGroupBucket;
import org.onosproject.net.group.DefaultGroupDescription;
import org.onosproject.net.group.DefaultGroupKey;
import org.onosproject.net.group.GroupBucket;
import org.onosproject.net.group.GroupBuckets;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupKey;
import org.onosproject.net.group.GroupService;

import org.onosproject.net.meter.MeterRequest;
import org.onosproject.net.meter.MeterService;
import org.onosproject.net.meter.Band;
import org.onosproject.net.meter.DefaultBand;
import org.onosproject.net.meter.DefaultMeterRequest;
import org.onosproject.net.meter.Meter;
import org.onosproject.net.meter.MeterId;

import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.PointToPointIntent;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.Collection;

@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final HostConfigListener cfgListener = new HostConfigListener();
    private final ConfigFactory<ApplicationId, HostConfig> factory = new ConfigFactory<ApplicationId, HostConfig>(
            APP_SUBJECT_FACTORY, HostConfig.class, "informations") {
        @Override
        public HostConfig createConfig() {
            return new HostConfig();
        }
    };

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MeterService meterService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    private GroupMeterIntentProcessor processor = new GroupMeterIntentProcessor();
    private int flowPriority = 30;
    private ApplicationId appId;
    protected DeviceId devID1;
    protected DeviceId devID2;
    protected PortNumber port1;
    protected PortNumber port2;
    protected MacAddress mac1;
    protected MacAddress mac2;
    protected IpAddress ip1;
    protected IpAddress ip2;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nycu.winlab.groupmeter");

        // flow rule + group entry
        GroupKey groupKey = new DefaultGroupKey(appId.name().getBytes());
        createFailoverGroup(devID1, groupKey);
        installFlowRuleGroup(devID1, groupKey);

        // flow rule + meter
        DeviceId deviceIds4 = DeviceId.deviceId("of:0000000000000004");
        MeterId meterId = installMeter(deviceIds4);
        installFlowRuleMeter(deviceIds4, meterId);

        // config listener
        cfgService.addListener(cfgListener);
        cfgService.registerConfigFactory(factory);

        // packet processor
        packetService.addProcessor(processor, PacketProcessor.director(2));

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        cfgService.removeListener(cfgListener);
        cfgService.unregisterConfigFactory(factory);
        packetService.removeProcessor(processor);
        processor = null;
        log.info("Stopped");
    }

    private void createFailoverGroup(DeviceId devId, GroupKey groupKey) {
        GroupId groupId = GroupId.valueOf(1);

        // bucket 1: outPort = 2 and watchPort = 2
        TrafficTreatment treatment1 = DefaultTrafficTreatment.builder()
                .setOutput(PortNumber.portNumber(2))
                .build();
        GroupBucket bucket1 = DefaultGroupBucket.createFailoverGroupBucket(treatment1,
                PortNumber.portNumber(2), groupId);

        // bucket 2: outPort = 3 and watchPort = 3
        TrafficTreatment treatment2 = DefaultTrafficTreatment.builder()
                .setOutput(PortNumber.portNumber(3))
                .build();
        GroupBucket bucket2 = DefaultGroupBucket.createFailoverGroupBucket(treatment2,
                PortNumber.portNumber(3), groupId);

        GroupBuckets buckets = new GroupBuckets(Arrays.asList(bucket1, bucket2));
        GroupDescription groupDescription = new DefaultGroupDescription(devId, GroupDescription.Type.FAILOVER, buckets,
                groupKey, groupId.id(), appId);

        groupService.addGroup(groupDescription);
    }

    private void installFlowRuleGroup(DeviceId devId, GroupKey groupKey) {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchInPort(PortNumber.portNumber(1))
                .matchEthType((short) 0x0800) // IPv4 EtherType
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .group(groupService.getGroup(devId, groupKey).id())
                .build();

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(devId)
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(flowPriority)
                .fromApp(appId)
                .makePermanent()
                .build();

        flowRuleService.applyFlowRules(flowRule);
        log.info("Flow rule installed on device {} and group {}", devId, selector, groupKey);
    }

    private MeterId installMeter(DeviceId devId) {
        Band dropBand = DefaultBand.builder()
                .ofType(Band.Type.DROP)
                .withRate(512) // Rate in KB per second
                .burstSize(1024) // Burst size
                .build();
        Collection<Band> bands = Collections.singletonList(dropBand);

        MeterRequest meterRequest = DefaultMeterRequest.builder()
                .fromApp(appId)
                .forDevice(devId)
                .withUnit(Meter.Unit.KB_PER_SEC)
                .withBands(bands)
                .burst() // set burst to true
                .add();

        Meter meter = meterService.submit(meterRequest);
        MeterId meterId = (MeterId) meter.meterCellId();
        log.info("Meter installed on device {} with ID {}", devId, meterId);

        return meterId;
    }

    private void installFlowRuleMeter(DeviceId devId, MeterId meterId) {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .add(Criteria.matchEthSrc(mac1))
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .meter(meterId)
                .setOutput(PortNumber.portNumber(2))
                .build();

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(devId)
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(flowPriority)
                .fromApp(appId)
                .makePermanent()
                .build();

        flowRuleService.applyFlowRules(flowRule);
        log.info("Flow rule installed on device {} with meter {}", devId, meterId);
    }

    private class HostConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
                    && event.configClass().equals(HostConfig.class)) {
                HostConfig config = cfgService.getConfig(appId, HostConfig.class);
                if (config != null) {
                    String[] id_port1 = config.host1().toString().split("/");
                    String[] id_port2 = config.host2().toString().split("/");
                    devID1 = DeviceId.deviceId(id_port1[0]);
                    devID2 = DeviceId.deviceId(id_port2[0]);
                    port1 = PortNumber.portNumber(id_port1[1]);
                    port2 = PortNumber.portNumber(id_port2[1]);
                    mac1 = MacAddress.valueOf(config.mac1().toString());
                    mac2 = MacAddress.valueOf(config.mac2().toString());
                    ip1 = IpAddress.valueOf(config.ip1().toString());
                    ip2 = IpAddress.valueOf(config.ip2().toString());
                    log.info("ConnectPoint_h1: {}, ConnectPoint_h2: {}", config.host1(), config.host2());
                    log.info("MacAddress_h1: {}, MacAddress _h2: {}", config.mac1(), config.mac2());
                    log.info("IpAddress_h1: {}, IpAddress_h2: {}", config.ip1(), config.ip2());
                }
            }
        }
    }

    private class GroupMeterIntentProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled())
                return;
            if (context.inPacket().parsed().getEtherType() != Ethernet.TYPE_IPV4)
                return;

            InboundPacket pkt = context.inPacket();
            ConnectPoint srcCP = pkt.receivedFrom();
            DeviceId recDevId = srcCP.deviceId();
            PortNumber recPort = srcCP.port();

            handleIntent(srcCP, recDevId, recPort);

            // deal with ARP
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null || !(ethPkt.getPayload() instanceof ARP))
                return;

            ARP arpPkt = (ARP) ethPkt.getPayload();
            MacAddress srcMac = MacAddress.valueOf(arpPkt.getSenderHardwareAddress());

            // ARP request from h1
            if (arpPkt.getOpCode() == ARP.OP_REQUEST && srcMac.equals(mac1)) {
                log.info("RECV REQUEST. Requested MAC = {}", srcMac);
                Ethernet ethReply = ARP.buildArpReply(ip2.getIp4Address(), mac2, ethPkt);
                TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(recPort).build();
                OutboundPacket packet = new DefaultOutboundPacket(recDevId, treatment,
                        ByteBuffer.wrap(ethReply.serialize()));
                packetService.emit(packet);
            }
        }

        private void handleIntent(ConnectPoint srcCP, DeviceId recDevId, PortNumber recPort) {
            ConnectPoint CP1 = new ConnectPoint(devID1, port1);
            ConnectPoint CP2 = new ConnectPoint(devID2, port2);

            FilteredConnectPoint ingress = new FilteredConnectPoint(srcCP);
            FilteredConnectPoint egress1 = new FilteredConnectPoint(CP1);
            FilteredConnectPoint egress2 = new FilteredConnectPoint(CP2);

            PointToPointIntent intent;
            TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();

            // s2(s5) to h2 IntentService
            selectorBuilder.matchEthDst(mac2);
            intent = PointToPointIntent.builder()
                    .appId(appId)
                    .filteredIngressPoint(ingress) // packet-in packet
                    .filteredEgressPoint(egress2) // h2
                    .selector(selectorBuilder.build())
                    .priority(flowPriority)
                    .build();
            intentService.submit(intent);
            log.info("Intent `{}`, port `{}` => `{}`, port `{}` is submitted.", recDevId, recPort, devID2, port2);

            // h2 to h1 IntentService
            selectorBuilder.matchEthDst(mac1);
            intent = PointToPointIntent.builder()
                    .appId(appId)
                    .filteredIngressPoint(ingress) // packet-in packet
                    .filteredEgressPoint(egress1) // h1
                    .selector(selectorBuilder.build())
                    .priority(flowPriority)
                    .build();
            intentService.submit(intent);
            log.info("Intent `{}`, port `{}` => `{}`, port `{}` is submitted.", recDevId, recPort, devID1, port1);
        }
    }
}
