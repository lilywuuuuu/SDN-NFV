# CONTAINER=h1 h2 R1 R2

# define link_netns
# 	mkdir -p /var/run/netns
# 	for cname in $(CONTAINER); do \
# 		pid=$$(docker inspect -f '{{.State.Pid}}' $$cname); \
# 		sudo ln -sfT /proc/$$pid/ns/net /var/run/netns/$$cname; \
# 	done
# endef

# ID = 7
# ID0 = 0$(ID)
# deploy:
# 	docker compose up -d
# 	$(call link_netns)

# 	# setup ovs1 and ovs2
# 	sudo ovs-vsctl add-br ovs1
# 	sudo ovs-vsctl add-br ovs2
# 	sudo ovs-vsctl set bridge ovs1 protocol=OpenFlow14
# 	sudo ovs-vsctl set bridge ovs2 protocol=OpenFlow14
# 	sudo ovs-vsctl set-controller ovs1 tcp:192.168.100.1:6653
# 	sudo ovs-vsctl set-controller ovs2 tcp:192.168.100.1:6653

# 	# add ovs1 ports
# 	sudo ovs-docker add-port ovs1 r1onos R1 --ipaddress=192.168.100.3/24
# 	sudo ovs-docker add-port ovs1 r1r2 R1 --ipaddress=192.168.63.1/24
# 	sudo ovs-docker add-port ovs1 r1h1 R1 --ipaddress=172.16.$(ID).69/24
# 	sudo ovs-docker add-port ovs1 r1ta R1 --ipaddress=192.168.70.$(ID)/24
# 	sudo ovs-docker add-port ovs1 r2all R2 --ipaddress=192.168.63.2/24
# 	sudo ovs-docker add-port ovs1 6r1r2 R1 --ipaddress=fd63::1/64
# 	sudo ovs-docker add-port ovs1 6r1h1 R1 --ipaddress=2a0b:4e07:c4:1$(ID0)::69/64
# 	sudo ovs-docker add-port ovs1 6r1ta R1 --ipaddress=fd70::$(ID)/64
# 	sudo ovs-docker add-port ovs1 6r2all R2 --ipaddress=fd63::2/64

# 	# add ovs2 ports
# 	sudo ovs-docker add-port ovs2 h1all h1 --ipaddress=172.16.$(ID).2/24
# 	sudo ovs-docker add-port ovs2 6h1all h1 --ipaddress=2a0b:4e07:c4:1$(ID0)::2/64
# 	sudo ovs-vsctl add-port ovs2 TO_TA_VXLAN -- set interface TO_TA_VXLAN type=vxlan options:local_ip=192.168.61.$(ID) options:remote_ip=192.168.60.$(ID)
	
# 	# link h1 to R1
# 	docker exec -it h1 ip route del default 2>/dev/null || true
# 	docker exec -it h1 ip route add default via 172.16.$(ID).69
# 	docker exec -it h1 ip -6 route del default 2>/dev/null || true
# 	docker exec -it h1 ip -6 route add default via 2a0b:4e07:c4:$(ID)::69

# 	# link onos and ovs2
# 	sudo ip link add vethos2 type veth peer name veths2o
# 	sudo ovs-vsctl add-port ovs2 veths2o
# 	sudo ip link set vethos2 up
# 	sudo ip link set veths2o up
# 	sudo ip addr add 192.168.100.1/24 dev vethos2

# 	# link ovs1 and ovs2
# 	sudo ip link add veths1s2 type veth peer name veths2s1
# 	sudo ovs-vsctl add-port ovs1 veths1s2
# 	sudo ovs-vsctl add-port ovs2 veths2s1
# 	sudo ip link set veths1s2 up
# 	sudo ip link set veths2s1 up

# 	# link R2 to h2
# 	sudo ip link add vethr2h2 type veth peer name vethh2r2
# 	sudo ip link set vethr2h2 netns R2
# 	sudo ip link set vethh2r2 netns h2
# 	sudo ip netns exec R2 ip link set vethr2h2 up
# 	sudo ip netns exec h2 ip link set vethh2r2 up
# 	sudo ip netns exec R2 ip addr add 172.17.$(ID).1/24 dev vethr2h2
# 	sudo ip netns exec h2 ip addr add 172.17.$(ID).2/24 dev vethh2r2
# 	sudo ip netns exec R2 ip -6 addr add 2a0b:4e07:c4:1$(ID0)::1/64 dev vethr2h2
# 	sudo ip netns exec h2 ip -6 addr add 2a0b:4e07:c4:1$(ID0)::2/64 dev vethh2r2
# 	docker exec -it h2 ip route del default 2>/dev/null || true
# 	docker exec -it h2 ip route add default via 172.17.$(ID).1
# 	docker exec -it h2 ip -6 route del default 2>/dev/null || true
# 	docker exec -it h2 ip -6 route add default via 2a0b:4e07:c4:1$(ID0)::1


# clean:
# 	sudo ovs-vsctl del-controller ovs1 || true
# 	sudo ovs-vsctl del-controller ovs2 || true
# 	sudo ovs-vsctl del-br ovs1 || true
# 	sudo ovs-vsctl del-br ovs2 || true

# 	docker compose down

# 	sudo ip l del vethos2 || true
# 	sudo ip l del veths2o || true
# 	sudo ip l del veths1s2 || true
# 	sudo ip l del veths2s1 || true
# 	sudo ip l del vethr2h2 || true
# 	sudo ip l del vethh2r2 || true

# 	for cname in $(CONTAINER); do \
# 		sudo ip netns delete $$cname || true; \
# 	done

# 	docker network prune -f

CONTAINER=h1 h2 R1 R2

define link_netns
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

ID = 8
ID0 = 0$(ID)

deploy:
	docker compose up -d
	$(call link_netns)
	sudo ovs-vsctl add-br ovs1
	sudo ovs-vsctl add-br ovs2
	sudo ovs-vsctl set bridge ovs1 protocol=OpenFlow14
	sudo ovs-vsctl set bridge ovs2 protocol=OpenFlow14
	sudo ovs-vsctl set-controller ovs1 tcp:192.168.100.1:6653
	sudo ovs-vsctl set-controller ovs2 tcp:192.168.100.1:6653

	sudo ovs-docker add-port ovs1 tonos R1 --ipaddress=192.168.100.3/24
	sudo ovs-docker add-port ovs1 tr2 R1 --ipaddress=192.168.63.1/24
	sudo ovs-docker add-port ovs1 tr1 R2 --ipaddress=192.168.63.2/24
	sudo ovs-vsctl add-port ovs2 TO_TA_VXLAN -- set interface TO_TA_VXLAN type=vxlan options:local_ip=192.168.61.$(ID) options:remote_ip=192.168.60.$(ID) 

	sudo ovs-docker add-port ovs2 tas h1 --ipaddress=172.16.$(ID).2/24
	sudo ovs-docker add-port ovs1 tas R1 --ipaddress=172.16.$(ID).69/24
	docker exec -it h1 ip route add default via 172.16.$(ID).79

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
	sudo ip link add vethr1ta type veth peer name vethtar1
	sudo ip link set vethtar1 up
	sudo ovs-vsctl add-port ovs1 vethtar1
	sudo ip link set vethr1ta netns R1
	sudo ip netns exec R1 ip link set vethr1ta up
	sudo ip netns exec R1 ip a a 192.168.70.$(ID)/24 dev vethr1ta

	# AS1
	@$(call create_as_veth, R2, h2, 172.17.7.1/24, 172.17.7.2/24)
	docker exec -it h2 ip r add default via 172.17.7.1


clean:
	sudo ovs-vsctl del-controller ovs1
	sudo ovs-vsctl del-controller ovs2
	sudo ovs-vsctl del-br ovs1
	sudo ovs-vsctl del-br ovs2
	docker compose down
	sudo ip l del veth0
	sudo ip l del veths1s2
	sudo ip l del vethtar1
	@basename -a /sys/class/net/veth* | grep -e '\([Rh][0-9]\)\{2\}' | xargs -I {} ip l del {} 2>/dev/null | true