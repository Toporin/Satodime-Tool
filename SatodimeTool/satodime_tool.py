import json
import time
import logging
import sys
#import traceback
from os import urandom

from pysatochip.CardConnector import CardConnector, UninitializedSeedError
#from pysatochip.JCconstants import JCconstants
#from pysatochip.Satochip2FA import Satochip2FA

try: 
    from client import Client
    from handler import HandlerSimpleGUI
except Exception as e:
    print('seedkeeper importError: '+repr(e))
    from SatodimeTool.client import Client
    from SatodimeTool.handler import HandlerSimpleGUI
                
# to run from source, in parent folder: python3 -m satodime_tool.py -v 
# alternatively, also in parent folder: python3 SatodimeTool/satodime_tool.py -v 

if (len(sys.argv)>=2) and (sys.argv[1]in ['-v', '--verbose']):
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
else:
    logging.basicConfig(level=logging.INFO, format='%(levelname)s [%(module)s] %(funcName)s | %(message)s')
logger = logging.getLogger(__name__)

logger.warning("loglevel: "+ str(logger.getEffectiveLevel()) )

handler= HandlerSimpleGUI(logger.getEffectiveLevel())
client= Client(None, handler, logger.getEffectiveLevel())
cc = CardConnector(client, logger.getEffectiveLevel(), "satodime")
time.sleep(1) # give some time to initialize reader...

while(True):
     
    event, values= client.main_menu() 
    logger.debug("Event: "+ str(event))
     
    if event in ['quit', None]:
        break;
    
    elif event== 'show_card_authenticity':
        card_info= client.truststore[client.authentikey.get_public_key_bytes(compressed=False).hex()]
        try: 
            handler.show_card_authenticity(card_info)
        except Exception as ex:
            logger.debug("Exception in  show_card_authenticity: "+ str(ex))
        
    elif event== 'transfer_card':
        client.transfer_card()
    
    elif event== 'refresh_card_info':
        client.card_event= True # force update of  variables storing state
        client.card_event_slots= range(client.max_num_keys)
    
    elif event.startswith("show_details"):
        event_split= event.split('_')
        key_nbr= int(event_split[2])
        
        # if key is unsealed, recover privkey info:
        privkey_info= client.get_privkey_info(key_nbr)
        # merge info
        client.satodime_keys_info[key_nbr].update(privkey_info)
        
        try: 
            handler.show_details(key_nbr, client.satodime_keys_status[key_nbr], client.satodime_keys_info[key_nbr])
        except Exception as ex:
            logger.debug("Exception in  details_menu: "+ str(ex))
    
    elif event.startswith("action_"):
        event_split= event.split('_')
        action= event_split[1]
        key_nbr= int(event_split[2])
        client.action_menu(action, key_nbr)
        
    elif event == 'about':
        handler.about_menu()
    elif event == 'help':
        handler.help_menu()
    else: 
        logger.debug("Unknown event: "+ str(event))
        break;

# print("DEBUG END satodime_tool.py ")
