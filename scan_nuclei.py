import json
import subprocess
import os, shutil
import tempfile
import pprint


FILE_SEPARATOR = "-"


class Nuclei:
	def __init__(self):
		Nuclei.update_templates()
		self.outputPath = f"{tempfile.gettempdir()}/"
		try:
			os.makedirs(os.path.expanduser(self.outputPath))
		except FileExistsError:
			pass


	@staticmethod
	def update_templates(verbose=True):
		processes = list()
		commands = [
			["nuclei", "-ut"],
		]
		
		for command in commands:
			processes.append(subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE))

		for process in processes:
			output, error = process.communicate()
			if verbose:
				print(f"[Stdout] {output.decode('utf-8', 'ignore')}")
				print(f"[Stderr] {error.decode('utf-8', 'ignore')}")

	@property
	def nuclei_templates(self):
		return [
			"cnvd", "cves", "default-logins", "exposed-panels",
			"exposures", "file", "misconfiguration",
			"miscellaneous", "takeovers", "technologies",
			"token-spray", "vulnerabilities", "network", 
			"dns", "iot", "ssl"
		]


	def create_report_dir(self, host):
		try:
			os.makedirs(os.path.expanduser(f"{self.outputPath}{host}"))
		except FileExistsError:
			pass


	def _parse_nuclei_scan(self, host, templates):
		report = list()

		for template in templates:
			try:
				with open(f"{self.outputPath}{host}{template}", "r") as scanResult:
					for result in scanResult.readlines():
						result = json.loads(result)
						report.append(result)
			except Exception as e:
				print(f"Exception while reading Nuclei Scan Result: {e}")

		return report

	
	def _format_nuclei_report(self, report):
		formatted_report = list()
		for vuln in report:
			try:
				data = {
					"templateId": vuln["template-id"],
					"host": vuln["host"],
					"vulnerabilityName": vuln["info"]["name"],
					"vulnerabilityDetail": str(),
					"description": str(),
					"type": vuln["type"],
					"result": list(),
					"vulnerableAt": vuln["matched-at"],
					"solution": str(),
					"curl": str(),
					"severity": vuln["info"]["severity"],
					"tags": vuln["info"]["tags"],
					"reference": str(),
					"cvss-metrics": str(),
					"cvss-score": None,
					"cve-id": str(),
					"cwe-id": None
				}
				if "description" in vuln["info"]:
					data["description"] = vuln["info"]["description"]

				if "severity" in vuln["info"]:
					data["severity"] = vuln["info"]["severity"]

				if "reference" in vuln["info"]:
					if vuln["info"]["reference"]:
						if type(vuln["info"]["reference"]) is str:
							data["reference"] = vuln["info"]["reference"]
						else:
							data["reference"] =  ", ".join(vuln["info"]["reference"])
				
				if "remediation" in vuln["info"]:
					data["solution"] = vuln["info"]["remediation"]

				if "classification" in vuln["info"]:

					if "cvss-metrics" in vuln["info"]["classification"]:
						data["cvss-metrics"] = vuln["info"]["classification"]["cvss-metrics"]

					if "cvss-score" in vuln["info"]["classification"]:
						data["cvss-score"] = vuln["info"]["classification"]["cvss-score"]
					
					if "cve-id" in vuln["info"]["classification"]:
						data["cve-id"] = vuln["info"]["classification"]["cve-id"]
					
					if "cwe-id" in vuln["info"]["classification"]:
						cwe = 0
						if type(vuln["info"]["classification"]["cwe-id"]) is list and vuln["info"]["classification"]["cwe-id"]:
							cwe = vuln["info"]["classification"]["cwe-id"][0]
						else:
							cwe = vuln["info"]["classification"]["cwe-id"]

						if "cwe-" in cwe:
							data["cwe-id"] = int(cwe.split("-")[-1])
					
				if "extracted-results" in vuln:
					data["result"] = vuln["extracted-results"]

				if "curl-command" in vuln:
					data["curl"] = vuln["curl-command"]

				if "matcher-name" in vuln:
					data["vulnerabilityDetail"] = vuln["matcher-name"]
							
				formatted_report.append(data)
			except Exception as e:
				print(f"Error in parsing Nuclei result: {e} | Data: {vuln}")
				continue
		
		return formatted_report

	
	def scan(self, host, templates=[], rateLimit=150, verbose=False):
		fileNameValidHost = f"{host.replace('/', FILE_SEPARATOR)}/"
		self.create_report_dir(fileNameValidHost)
		allScans = list()

		if not templates:
			templates = self.nucleiTemplates

		for template in templates:
			command = [
				'nuclei',"-rl", str(rateLimit), "-u", host, "-t", f"{template}/", 
				"-json", "-o", f"{self.outputPath}{fileNameValidHost}{template}", 
				"-disable-update-check"
			]
			allScans.append(subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE))

		for process in allScans:
			output, error = process.communicate()
			if verbose:
				print(f"[Stdout] [{host}] {output.decode('utf-8', 'ignore')}")
				print(f"[Stderr] [{host}] {error.decode('utf-8', 'ignore')}")

		report = self._parse_nuclei_scan(fileNameValidHost, templates)

		shutil.rmtree(f"{self.outputPath}{fileNameValidHost}", ignore_errors=True)

		return self._format_nuclei_report(report)

if __name__ == '__main__':
	nucleiScanner = Nuclei()
	scanResult = nucleiScanner.scan("URL", templates=[], rateLimit=150)
	pprint.pprint(scanResult)