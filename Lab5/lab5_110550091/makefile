IMAGE_NAME = host

# Build the docker image
build:
	docker build -t $(IMAGE_NAME) -f host.Dockerfile .

# Set up the environment
main: build
	docker compose up -d
	sudo ovs-vsctl add-br ovsbr
	sudo ovs-vsctl set bridge ovsbr protocols=OpenFlow14
	sudo ovs-vsctl set-controller ovsbr tcp:127.0.0.1:6653
	sudo ovs-docker add-port ovsbr eth1 R1 --ipaddress=172.20.0.2/16
	sudo ovs-docker add-port ovsbr eth2 R3 --ipaddress=172.20.0.3/16
	sudo ovs-docker add-port ovsbr eth3 R4 --ipaddress=172.20.0.4/16

# Clean up the environment
clean:
	docker compose down
	sudo ovs-vsctl del-br ovsbr