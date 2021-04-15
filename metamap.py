import nmap3
import vulners
import sys

def welcome():
	print("""
  __  __ ______ _______       __  __          _____
 |  \/  |  ____|__   __|/\   |  \/  |   /\   |  __ \\
 | \  / | |__     | |  /  \  | \  / |  /  \  | |__) |
 | |\/| |  __|    | | / /\ \ | |\/| | / /\ \ |  ___/
 | |  | | |____   | |/ ____ \| |  | |/ ____ \| |
 |_|  |_|______|  |_/_/    \_\_|  |_/_/    \_\_|
====================================================

Nmap/Vulners Automated Vulnerability scanning tool

Author: @su__charlie

====================================================""")

def usage():
	print(f"""
Usage Information
===================

python3 {__file__} [args] target

Arguments:
===========
\tYou can pass any Nmap arguments to refine your query.

Example:
===========
\tpython3 {__file__} -p22,23,80,8080 -T4 192.168.1.10

""")

class Scanner:
	"""Scan host and check for exploits"""
	nmap = nmap3.Nmap()

	def __init__(self, key):
		self.vulners_api = vulners.Vulners(api_key=key)

	def prepare(self):
		self.host = sys.argv[-1]
		self.args = ' '.join(sys.argv[1:-1])

	def scan(self):
		self.results = self.nmap.nmap_version_detection(self.host, args=self.args)

	def parse_results(self):
		self.parsed_results = {}
		for host in self.results:
			if(host != "stats" and host != "runtime"):
				ports = []
				for port in self.results[host]['ports']:
					ports.append(
						{
						"proto": port['protocol'],
						"port": port['portid'],
						"state": port['state'],
						"name": port['service']['name'],
						"product":port['service']['product'] if 'product' in port['service'] else '',
						"version": port['service']['version'] if 'version' in port['service'] else ''
						})
				self.parsed_results[host] =  ports

	def get_exploits(self, name, version):
		results = self.vulners_api.softwareVulnerabilities(name, version)
		exploit_list = results.get('exploit')
		return [results.get(key) for key in results if key not in ['info', 'blog', 'bugbounty']]


	def show_results(self):
		print(f"\nShowing {len(self.parsed_results)} results from Metamap Scan")
		for host in self.parsed_results:
			print(f"\nScan results for ({host})")
			for port in self.parsed_results[host]:
				print(f"{port['proto']}/{port['port'].ljust(20)}{port['state'].ljust(20)}{port['name']}/{port['product']} {port['version']}")
				if port['product'] != '' and port['version'] != '':
					exploits = self.get_exploits(port['product'], port['version'])
					if(exploits != []):
						for exploit in exploits[0]:
							print(f"\t{','.join(exploit['cvelist'])}: {exploit['title']}")
		print(f"\nCommand {self.results['stats']['args']} executed in {self.results['runtime']['elapsed']} seconds.")


if __name__ == "__main__":
	welcome()
	if len(sys.argv) < 2:
		usage()
	elif "-h" in sys.argv or "--help" in sys.argv:
		usage()
	else:
		scanner = Scanner(input("You need to provide a Vulners API key. \nYou can get one here: https://vulners.com/\n\nVulners API Key: "))
		scanner.prepare()
		scanner.scan()
		scanner.parse_results()
		scanner.show_results()
