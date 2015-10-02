from mininet.topo import Topo
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.log import setLogLevel

class tendril( Topo ) :
	"""Create a leaf topology"""
	
	def __init__( self, k=4, h=6 ):

		# Initialize topology
		Topo.__init__( self )
		
		spines = []
		leaves = []
		hosts = []

		# Create the two spine switches
		spines.append(self.addSwitch('s1'))
		spines.append(self.addSwitch('s2'))

		# Create two links between the spine switches
		self.addLink(spines[0], spines[1])
		# TODO add second link between spines when multi-link topos are supported
		#self.addLink(spines[0], spines[1])

		# Now create the leaf switches, their hosts and connect them together
		i = 1
		c = 0
		while i <= k:
			leaves.append(self.addSwitch('s1%d' % i ))
			for spines in spines:
				self.addLink(leaves[i-1], spines)

			j = 1
			while j <= h:
				hosts.append(self.addHost('h%d%d' % (i, j)))
				self.addLink(hosts[c], leaves[i-1])
				j += 1
				c += 1

			i += 1

topos = { 'tendril': tendril } 

def run():
	topo = tendril()
	net = Mininet ( topo=topo, controller=RemoteController, autoSetMacs=True)
	net.start()
	CLI( net )
	net.stop()

if __name__ == '__main__':
	setLogLevel( 'info' )
	run()
