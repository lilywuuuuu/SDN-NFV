from mininet.topo import Topo

class Demo1_Topo_110550091( Topo ):
	def __init__(self):
		Topo.__init__(self)
		
		# Add hosts
		h1 = self.addHost('h1', ip='192.168.130.1/27')
		h2 = self.addHost('h2', ip='192.168.130.2/27')
		h3 = self.addHost('h3', ip='192.168.130.3/27')
		
		#Add switches
		s1 = self.addSwitch('s1')

		#Add links
		self.addLink(h1, s1)
		self.addLink(h2, s1)
		self.addLink(h3, s1)

		
topos = { 'mytopo': Demo1_Topo_110550091}