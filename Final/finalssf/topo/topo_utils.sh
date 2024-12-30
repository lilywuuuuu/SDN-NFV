#!/bin/bash
#set -x

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Creates a veth pair
# params: endpoint1 endpoint2
function create_veth_pair {
    ip link add $1 type veth peer name $2
    ip link set $1 up
    ip link set $2 up
    sysctl -w net.ipv6.conf.$1.autoconf=0
    sysctl -w net.ipv6.conf.$2.autoconf=0
    ip -6 addr flush dev $1
    ip -6 addr flush dev $2
}

# Add a container with a certain image
# params: image_name container_name
function add_container {
	docker run -dit --network=none --privileged --cap-add NET_ADMIN --cap-add SYS_MODULE \
		 --hostname $2 --name $2 ${@:3} $1
	pid=$(docker inspect -f '{{.State.Pid}}' $(docker ps -aqf "name=$2"))
	mkdir -p /var/run/netns
	ln -s /proc/$pid/ns/net /var/run/netns/$pid
}

# Remove ipv6 autoconf
# params: container_name interface_name
function remove_v6_autoconf {
    pid=$(docker inspect -f '{{.State.Pid}}' $(docker ps -aqf "name=$1"))
    ip netns exec "$pid" sysctl -w net.ipv6.conf.$2.autoconf=0
    ip netns exec "$pid" ip -6 addr flush dev $2
}

# Remove a container with a certain name
# params: container_name
function remove_container {
    pid=$(docker inspect -f '{{.State.Pid}}' $(docker ps -aqf "name=$1"))
	[ -n "$pid" ] && [ -f "/var/run/netns/$pid" ] && rm /var/run/netns/$pid
    
    docker stop $1
    docker rm $1
}

# Set container interface's ip address and gateway
# params: container_name infname [ipaddress] [gw addr]
function set_intf_container {
    pid=$(docker inspect -f '{{.State.Pid}}' $(docker ps -aqf "name=$1"))
    ifname=$2
    ipaddr=$3
    echo "Add interface $ifname with ip $ipaddr to container $1"

    ip link show "$ifname" 2>/dev/null | grep -q "$ifname" && ip link set "$ifname" netns "$pid"

    [ $# -ge 3 ] && ip netns exec "$pid" ip addr add "$ipaddr" dev "$ifname"

    ip netns exec "$pid" ip link set "$ifname" up

    [ $# -ge 4 ] && ip netns exec "$pid" route add default gw $4
}

# Set container interface's ipv6 address and gateway
# params: container_name infname [ipaddress] [gw addr]
function set_v6intf_container {
    pid=$(docker inspect -f '{{.State.Pid}}' $(docker ps -aqf "name=$1"))
    ifname=$2
    ipaddr=$3
    echo "Add interface $ifname with ip $ipaddr to container $1"

    ip link show "$ifname" 2>/dev/null | grep -q "$ifname" && ip link set "$ifname" netns "$pid"

    [ $# -ge 3 ] && ip netns exec "$pid" ip addr add "$ipaddr" dev "$ifname"

    ip netns exec "$pid" ip link set "$ifname" up

    [ $# -ge 4 ] && ip netns exec "$pid" route -6 add default gw $4
}

# Connects the bridge and the container
# params: veth0 veth1 bridge_name container_name [ipaddress] [gw addr]
function build_bridge_container_path {
    br_inf=$1
    container_inf=$2
    create_veth_pair $br_inf $container_inf
    brctl addif $3 $br_inf
    set_intf_container $4 $container_inf $5 $6
}

# Connects two ovsswitches
# params: veth0 veth1 ovs1 ovs2
function build_ovs_path {
    create_veth_pair $1 $2
    ovs-vsctl add-port $3 $1
    ovs-vsctl add-port $4 $2
}

# Connects a container to an ovsswitch
# params: veth0 veth1 ovs container [ipaddress] [gw addr]
function build_ovs_container_path {
    ovs_inf=$1
    container_inf=$2
    create_veth_pair $ovs_inf $container_inf
    ovs-vsctl add-port $3 $ovs_inf
    set_intf_container $4 $container_inf $5 $6
}

PEERID=37
MYID=38

HOST_IMAGE=sdnfinal-host
FRR_IMAGE=sdnfinal-frrouting

H1_CONTAINER=h1
H2_CONTAINER=h2
FRR_CONTAINER=frr
ONOS_CONTAINER=onos
R1_CONTAINER=r1
OVS1=ovs1
OVS2=ovs2
VETH_VXLANTA=vethvxlanta
VETH_OVS1OVS2=vethovs1ovs2
VETH_OVS2H1=vethovs2h1
VETH_OVS1FRR=vethovs1frr
VETH_R1H2=vethr1h2
VETH_OVS1R1=vethovs1r1

function deploy {

    # Build host and frr image
    if ! docker images | awk 'NR>1 { print }' | grep -q $HOST_IMAGE; then
        docker build containers/host -t $HOST_IMAGE
    fi

    if ! docker images | awk 'NR>1 { print }' | grep -q $FRR_IMAGE; then
        docker build containers/frr -t $FRR_IMAGE
    fi

    # vxlan interface
    create_veth_pair ${VETH_VXLANTA}0 ${VETH_VXLANTA}1
    ip a add 192.168.100.1/24 dev ${VETH_VXLANTA}1

    # Start onos, hosts and ovs

    # If you want to test topology, add "fwd" to ONOS_APPS to activate the fwd app
    docker run -dit --privileged --hostname $ONOS_CONTAINER --name $ONOS_CONTAINER \
        -e ONOS_APPS=drivers,openflow,fpm,gui2 \
        -p 2620:2620 \
        -p 6653:6653 \
        -p 8101:8101 \
        -p 8181:8181 \
        --tty \
        --interactive \
        onosproject/onos:2.7.0

    add_container $HOST_IMAGE $H1_CONTAINER

    add_container $HOST_IMAGE $H2_CONTAINER

    add_container $FRR_IMAGE $FRR_CONTAINER \
        -v ./config/daemons:/etc/frr/daemons \
        -v ./config/frr/frr.conf:/etc/frr/frr.conf

    add_container $FRR_IMAGE $R1_CONTAINER \
        -v ./config/daemons:/etc/frr/daemons \
        -v ./config/r1/frr.conf:/etc/frr/frr.conf

    # ovs1 and ovs2
    ovs-vsctl add-br $OVS1 -- \
        set bridge $OVS1 protocols=OpenFlow14 -- \
        set-controller $OVS1 tcp:192.168.100.1:6653

    ovs-vsctl add-br $OVS2 -- \
        set bridge $OVS2 protocols=OpenFlow14 -- \
        set-controller $OVS2 tcp:192.168.100.1:6653

    build_ovs_path ${VETH_OVS1OVS2}0 ${VETH_OVS1OVS2}1 $OVS1 $OVS2

    # ovs2 to ovs3 (ta)
    ovs-vsctl add-port $OVS2 vxta -- set interface vxta type=vxlan options:remote_ip=192.168.60.$MYID
    ovs-vsctl add-port $OVS2 ${VETH_VXLANTA}0

    # ovs2 and h1
    build_ovs_container_path ${VETH_OVS2H1}0 ${VETH_OVS2H1}1 $OVS2 $H1_CONTAINER 172.16.$MYID.2/24 172.16.$MYID.1
    remove_v6_autoconf $H1_CONTAINER ${VETH_OVS2H1}1
    set_v6intf_container $H1_CONTAINER ${VETH_OVS2H1}1 2a0b:4e07:c4:$MYID::2/64 2a0b:4e07:c4:$MYID::1
    
    # ovs1 and frr
    build_ovs_container_path ${VETH_OVS1FRR}0 ${VETH_OVS1FRR}1 $OVS1 $FRR_CONTAINER 172.16.$MYID.69/24 172.16.$MYID.1
    remove_v6_autoconf $FRR_CONTAINER ${VETH_OVS1FRR}1
    set_intf_container $FRR_CONTAINER ${VETH_OVS1FRR}1 192.168.100.3/24
    set_intf_container $FRR_CONTAINER ${VETH_OVS1FRR}1 192.168.63.1/24
    set_intf_container $FRR_CONTAINER ${VETH_OVS1FRR}1 192.168.70.$MYID/24
    set_v6intf_container $FRR_CONTAINER ${VETH_OVS1FRR}1 fd63::1/64
    set_v6intf_container $FRR_CONTAINER ${VETH_OVS1FRR}1 fd70::$MYID/64
    set_v6intf_container $FRR_CONTAINER ${VETH_OVS1FRR}1 2a0b:4e07:c4:$MYID::69/64 2a0b:4e07:c4:$MYID::1

    # connect r1 and h2
    create_veth_pair ${VETH_R1H2}0 ${VETH_R1H2}1
    set_intf_container $R1_CONTAINER ${VETH_R1H2}0 172.17.38.1/24
    remove_v6_autoconf $R1_CONTAINER ${VETH_R1H2}0
    set_v6intf_container $R1_CONTAINER ${VETH_R1H2}0 2a0b:4e07:c4:1$MYID::1/64

    set_intf_container $H2_CONTAINER ${VETH_R1H2}1 172.17.38.2/24 172.17.38.1
    remove_v6_autoconf $H2_CONTAINER ${VETH_R1H2}1
    set_v6intf_container $H2_CONTAINER ${VETH_R1H2}1 2a0b:4e07:c4:1$MYID::2/64 2a0b:4e07:c4:1$MYID::1

    # ovs1 and r1
    build_ovs_container_path ${VETH_OVS1R1}0 ${VETH_OVS1R1}1 $OVS1 $R1_CONTAINER 192.168.63.2/24
    remove_v6_autoconf $R1_CONTAINER ${VETH_OVS1R1}1
    set_v6intf_container $R1_CONTAINER ${VETH_OVS1R1}1 fd63::2/64
    ovs-vsctl set interface ${VETH_OVS1R1}0 ingress_policing_rate=1000000
    docker exec ${R1_CONTAINER} ip -c a

    # ovs2 and peer
    ovs-vsctl add-port $OVS2 vxpeer -- set interface vxpeer type=vxlan options:remote_ip=192.168.61.$PEERID

    return 0
}

function gen_config {
    [ -z $1 ] && [ ! -f $1 ] && usage

    CONF_FILE=$1

    local conf="{
        \"ports\": {
            \"OVS1_AS65XX1\": {
                \"interfaces\": [
                    {
                        \"name\": \"ovs1 to AS65${MYID}1\",
                        \"ips\": [
                            \"192.168.63.1/24\",
                            \"fd63::1/64\"
                        ]
                    }
                ]
            },
            \"OVS3_AS65000\": {
                \"interfaces\": [
                    {
                        \"name\": \"ovs3 to AS65000\",
                        \"ips\": [
                            \"192.168.70.$MYID/24\",
                            \"fd70::38/64\"
                        ]
                    }
                ]
            },
            \"OVS2_AS65PEER\": {
                \"interfaces\": [
                    {
                        \"name\": \"ovs2 to AS65PEER\",
                        \"ips\": [
                            \"192.168.55.$MYID/24\"
                        ]
                    }
                ]
            }
        },
        \"apps\": {
            \"nycu.sdnfv.vrouter\": {
                \"router\": {
                    \"frrouting-cp\": \"FRR_CP\",
                    \"frrouting-mac\": \"FRR_MAC\",
                    \"gateway-ip4\": \"172.16.$MYID.1\",
                    \"gateway-ip6\": \"2a0b:4e07:c4:$MYID::1\",
                    \"gateway-mac\": \"00:01:10:55:00:17\",
                    \"wan-port-ip4\": [
                        \"192.168.70.$MYID\",
                        \"192.168.63.1\",
                        \"192.168.55.$MYID\"
                    ],
                    \"wan-port-ip6\": [
                        \"fd70::$MYID\",
                        \"fd63::1\"
                    ],
                    \"v4-peer\": [
                        \"192.168.70.0/24\",
                        \"192.168.63.0/24\",
                        \"192.168.55.0/24\"
                    ],
                    \"v6-peer\": [
                        \"fd70::/64\",
                        \"fd63::/64\"
                    ]
                }
            }
        }
    }"

    OVS1_DPID="of:$(ovs-vsctl get bridge ovs1 datapath-id | tr -d '"')"
    OVS2_DPID="of:$(ovs-vsctl get bridge ovs2 datapath-id | tr -d '"')"
    OVS3_DPID=$(curl -s -u onos:rocks http://localhost:8181/onos/v1/devices | jq -r '.devices[].id'| grep -v -E "$OVS1_DPID"'|'"$OVS2_DPID")

    AS65XX1_WAN_PORT=3
    
    AS65000_WAN_PORT=3

    FRR_CP="${OVS1_DPID}/2"

    FRR_MAC=$(docker exec frr ip link show ${VETH_OVS1FRR}1 | awk 'NR>1 {$1=$1; print}' | cut -d ' ' -f2)

    OVS2_AS65PEER="${OVS2_DPID}/5"

    conf=$(echo $conf | sed 's-OVS1_AS65XX1-'$OVS1_DPID/$AS65XX1_WAN_PORT'-g' | \
            sed 's-OVS3_AS65000-'$OVS3_DPID/$AS65000_WAN_PORT'-g' | \
            sed 's-FRR_CP-'$FRR_CP'-g' | \
            sed 's-FRR_MAC-'$FRR_MAC'-g' | \
            sed 's-OVS2_AS65PEER-'$OVS2_AS65PEER'-g')
    
    tee $CONF_FILE <<< "$conf"
}

function clean {
    remove_container $H1_CONTAINER
    remove_container $H2_CONTAINER
    remove_container $FRR_CONTAINER
    remove_container $R1_CONTAINER
    remove_container $ONOS_CONTAINER
    ovs-vsctl del-br $OVS1
    ovs-vsctl del-br $OVS2
    ip link del ${VETH_VXLANTA}0
    ip link del ${VETH_OVS1OVS2}0
}

function usage() {
    echo "Usage: ./topo_utils.sh [deploy | clean | gen-config INTERFACE_CONF APP_CONF]"
    exit 1
}

case $1 in
    "clean")
        clean
    ;;
    "deploy")
        deploy
    ;;
    "gen-config")
        shift
        gen_config $@
    ;;
    *)
        usage
    ;;
esac