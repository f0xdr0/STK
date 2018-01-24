usage: manager.py [-h] -cmd {logon,logoff,set_tarif,naton,natoff} -bras
                  {Belgorod,StOskol,Test} -ip CLIENTIP [-tarif_id TARIFID]
                  [-white_ip WHITEIP]

Управление BRAS

optional arguments:
  -h, --help            show this help message and exit
  -cmd {logon,logoff,set_tarif,naton,natoff}
                        Executable command
  -bras {Belgorod,StOskol,Test}
                        Bras name from config.yaml
  -ip CLIENTIP          Client ip address
  -tarif_id TARIFID     Tariff ID (see config.yaml)
  -white_ip WHITEIP     White ip for 1to1 NAT
