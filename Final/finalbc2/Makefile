CONTAINER=h1 h2 R1 R2

define netns
	mkdir -p /var/run/netns
	for cname in $(CONTAINER); do \
		pid=$$(docker inspect -f '{{.State.Pid}}' $$cname); \
		sudo ln -sfT /proc/$$pid/ns/net /var/run/netns/$$cname; \
	done
endef

define create_as_veth
	$(eval $@_C1 = $(1))
	$(eval $@_C2 = $(2))
	$(eval $@_IP1= $(3))
	$(eval $@_IP2= $(4))
	$(eval $@_L1=veth${$@_C1}${$@_C2})
	$(eval $@_L2=veth${$@_C2}${$@_C1})
	sudo ip link add ${$@_L1} type veth peer name ${$@_L2}
	sudo ip link set ${$@_L1} netns ${$@_C1}
	sudo ip link set ${$@_L2} netns ${$@_C2}
	sudo ip netns exec ${$@_C1} ip link set ${$@_L1} up
	sudo ip netns exec ${$@_C2} ip link set ${$@_L2} up
	sudo ip netns exec ${$@_C1} ip a a ${$@_IP1} dev ${$@_L1}
	sudo ip netns exec ${$@_C2} ip a a ${$@_IP2} dev ${$@_L2}
endef

define remove_autoconf
	$(eval $@_container = $(1))
	$(eval $@_intf = $(2))
	sudo ip netns exec ${$@_container} sysctl -w net.ipv6.conf.${$@_intf}.autoconf=0
	sudo ip netns exec ${$@_container} ip -6 addr flush dev ${$@_intf}
endef

deploy:
	docker compose up -d
	$(call netns)
	sudo ovs-vsctl add-br ovs1
	sudo ovs-vsctl add-br ovs2
	sudo ovs-vsctl set bridge ovs1 protocol=OpenFlow14 other_config:datapath-id=0x00006277774a224f
	sudo ovs-vsctl set bridge ovs2 protocol=OpenFlow14 other_config:datapath-id=0x00006277784a224f
	sudo ovs-vsctl set-controller ovs1 tcp:192.168.100.1:6653
	sudo ovs-vsctl set-controller ovs2 tcp:192.168.100.1:6653

	sudo ovs-docker add-port ovs1 tonos R1 --ipaddress=192.168.100.3/24
	sudo ovs-docker add-port ovs1 tr2 R1 --ipaddress=192.168.63.1/24 --macaddress="16:15:3d:d9:45:46"
	$(call remove_autoconf, R1, tr2)
	docker exec -it R1 ip -6 addr add fd63::1/64 dev tr2
	sudo ovs-docker add-port ovs1 tr1 R2 --ipaddress=192.168.63.2/24
	$(call remove_autoconf, R2, tr1)
	docker exec -it R2 ip -6 addr add fd63::2/64 dev tr1
	sudo ovs-vsctl add-port ovs2 TO_TA_VXLAN -- set interface TO_TA_VXLAN type=vxlan options:remote_ip=192.168.60.7

	sudo ovs-docker add-port ovs2 tas h1 --ipaddress=172.16.7.2/24
	$(call remove_autoconf, h1, tas)
	docker exec -it h1 ip -6 addr add 2a0b:4e07:c4:7::2/64 dev tas
	sudo ovs-docker add-port ovs1 tas R1 --ipaddress=172.16.7.69/24
	$(call remove_autoconf, R1, tas)
	docker exec -it R1 ip -6 addr add 2a0b:4e07:c4:7::69/64 dev tas
	docker exec -it h1 ip route add default via 172.16.7.1
	docker exec -it h1 ip -6 route add default via 2a0b:4e07:c4:7::1

	# veth 192.168.100.1 for onos and ovs2 
	sudo ip link add veth0 type veth peer name veth1
	sudo ovs-vsctl add-port ovs2 veth0
	sudo ip link set veth0 up
	sudo ip link set veth1 up
	sudo ip a add 192.168.100.1/24 dev veth1
	# link ovs1 and ovs2
	sudo ip link add veths1s2 type veth peer name veths2s1
	sudo ovs-vsctl add-port ovs1 veths1s2
	sudo ovs-vsctl add-port ovs2 veths2s1
	sudo ip link set veths1s2 up
	sudo ip link set veths2s1 up

	# link to IXP
	sudo ovs-docker add-port ovs1 tixp R1 --ipaddress=192.168.70.7/24 --macaddress="22:40:06:8b:90:1e"
	$(call remove_autoconf, R1, tixp)
	docker exec -it R1 ip -6 addr add fd70::7/64 dev tixp

	# AS1
	@$(call create_as_veth, R2, h2, 172.17.7.1/24, 172.17.7.2/24)
	docker exec -it h2 ip -6 addr add 2a0b:4e07:c4:107::2/64 dev vethh2R2
	docker exec -it R2 ip -6 addr add 2a0b:4e07:c4:107::1/64 dev vethR2h2
	docker exec -it h2 ip r add default via 172.17.7.1
	docker exec -it h2 ip -6 route add default via 2a0b:4e07:c4:107::1

	# sleep 15
	# onos-app localhost install! target/bridge-app-1.0-SNAPSHOT.oar
	# onos-app localhost install! target/ProxyArp-1.0-SNAPSHOT.oar
test:
	
install: 
	onos-netcfg localhost interface_config.json
	onos-app localhost install! src/vrouter/target/vrouter-app-1.0-SNAPSHOT.oar
	onos-app localhost install! src/ProxyArp/target/ProxyArp-1.0-SNAPSHOT.oar
	onos-app localhost install! src/bridge-app/target/bridge-app-1.0-SNAPSHOT.oar	
	
compile:
	mvn clean install -DskipTests
clean:
	sudo ovs-vsctl del-controller ovs1
	sudo ovs-vsctl del-controller ovs2
	sudo ovs-vsctl del-br ovs1
	sudo ovs-vsctl del-br ovs2
	sudo ip l del veth0
	sudo ip l del veths1s2
	docker compose down
	@basename -a /sys/class/net/veth* | grep -e '\([Rh][0-9]\)\{2\}' | xargs -I {} ip l del {} 2>/dev/null | true

testclean:
