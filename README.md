
## TruSTAR Resilient

The resulting .tar.gz file can be installed using:

	pip install <filename>.tar.gz

Add TruSTAR configuration details to the config file:

    resilient-circuits configure -u
	
Set the following values in the config file under the `[trustar_threat_source]` section:

	url = //<trustar url>
	user_api_key = //<Do not change>
	user_api_secret = //<Do not change>
	enclave_ids_for_search = //<list of enclave ids>


Set the following values in the config file under the `[trustar_account_n]` section:
User can configure multiple TruStar accounts. Create separate stanza for each account.
Each account is associated with one or many Resilient workspaces.
Stanza name should start with trustar_ (e.g trustar_prod)

	url = //<trustar url>
	user_api_key = //<^api_key_for_[stanza name (for e.g trustar_account_n)]>
	user_api_secret = //<^api_secret_for_[stanza name (for e.g trustar_account_n)]>
	enclave_ids_for_submission = //<list of enclave ids>
	enclave_ids_for_query = //<list of enclave ids>
	auto_submission = //<enable|disable>
	incident_content_to_submit = //<List of data>
	incident_types_to_exclude = //<Types to exclude>
	workspace = //<list of workspaces>
	tag = //<tag name>

Set the following values in the config file under the `[webserver]` section:

	server = //Host IP where resilient-circuits is running
	port = //port on host
	secure = //Secure protocol https or http
	cafile = //certificate file, needed in case of secure = 1
	
Note: Do not change the values under [`custom_threat_service`] section.
    
### How to use the function

1. Import the necessary customization data into the Resilient Platform:

		resilient-circuits customize

2. Update and edit `app.config`:

		resilient-circuits configure -u

3. After changing values in config file run following command.
		
		res-keyring
		
		a. Here you will need to provide values like API KEY and API SECRET.

3. Start Resilient Circuits with:
    Run the integration framework

	###Steps for Linux
		a.	Create a service file using following command.
			sudo vi /etc/systemd/system/resilient_circuits.service
		b.	Add following content in that .service file:
				[Unit]
				Description=Resilient-Circuits Service
				After=resilient.service
				Requires=resilient.service
				
				[Service]
				Type = simple
				User = root
				WorkingDirectory = /root
				ExecStartPre = /usr/bin/resutil threatsourceedit -name "TruSTAR" -resturl "http://127.0.0.1:9000/cts/trustar"
				ExecStart = /usr/local/bin/resilient-circuits run -r
				Restart = always
				TimeoutSec = 100
				
				[Install]
				WantedBy=multi-user.target
			Change locations in the file as per the environment. 
		c.	Ensure that the service unit file is correctly permissioned:
			sudo chmod 664 /etc/systemd/system/resilient_circuits.service
		d.	Use the systemctl command to manually start, stop, restart and return status on the service:
			sudo systemctl resilient_circuits [start|stop|restart|status]
		e.	Log files for systemd and the resilient-circuits service can be viewed through the journalctl command:
			sudo journalctl -u resilient_circuits --since "2 hours ago"

	###Steps for Windows
		a.	Run the following command from command prompt.
			resilient-circuits run -r
		b. Run the following command where your resilient platform is installed.
			sudo resutil threatserviceedit -name "TruSTAR" -resturl "{url}/cts/trustar"
				- In place of {url}, add value in this format: {http|https}://host_ip:{port_you_added_in_config_file}

