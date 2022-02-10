import PySimpleGUIQt as sg 
import logging
import json
import hashlib
import sys
from os import urandom, path, getcwd
from configparser import ConfigParser  

from pysatochip.CardConnector import CardConnector, UninitializedSeedError, SeedKeeperError, UnexpectedSW12Error, CardError, CardNotPresentError
from pysatochip.JCconstants import *
from pysatochip.version import SATODIME_PROTOCOL_MAJOR_VERSION, SATODIME_PROTOCOL_MINOR_VERSION, SATODIME_PROTOCOL_VERSION

#from cryptos import transaction, main #deserialize
from pycryptotools.coins import Bitcoin, BitcoinCash, Litecoin, Doge, Dash, Ethereum, BinanceSmartChain, EthereumClassic, xDai, RSK

# print("DEBUG START client.py ")
# print("DEBUG START client.py __name__: "+__name__)
# print("DEBUG START client.py __package__: "+str(__package__))

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# address from crypto hodlers for checking API
# based on https://tokenview.com/en/topaccount
DEBUG= False
DEBUG_ADDRS={
    "BTC":"34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo" ,
    "BCH":"1JBHhm7Z6i5i65epVg2fA676PCE7WVQyv1",
    "LTC":"M8T1B2Z97gVdvmfkQcAtYbEepune1tzGua",
    "DOGE":"DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L",
    "ETH":"0x577ebc5de943e35cdf9ecb5bbe1f7d7cb6c7c647", # holder cryptopunk
    "ETC":"0x78d5e220b4cc84f290fae4148831b371a851a114",
    "BSC":"0xf68a4b64162906eff0ff6ae34e2bb1cd42fef62d",
    "XDAI":"0x10E4597fF93cbee194F4879f8f1d54a370DB6969",
}
DEBUG_CONTRACT={
    "ETH":"0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb", # cryptopunk
    "ETC":"0x6ada6f48c815689502c43ec1a59f1b5dd3c04e1f",# UniversalCoin
    "BSC":"0x2170ed0880ac9a755fd29b2688956bd959f933f8", # Binance-Peg Ethereum Token
}
       
       
try: 
    from handler import DIC_CODE_BY_ASSET
    from slip44 import DICT_SLIP44_BY_SYMBOL
except Exception as e:
    print('handler.py importError: '+repr(e))
    from .handler import DIC_CODE_BY_ASSET
    from .slip44 import DICT_SLIP44_BY_SYMBOL
       
class Client:
            
    def __init__(self, cc, handler, loglevel= logging.WARNING):
        logger.setLevel(loglevel)
        logger.debug("In __init__")
        self.handler = handler
        self.handler.client= self
        self.cc= cc
        self.truststore={}

        self.card_label= ''
        self.authentikey= None
        self.authentikey_comp_hex= None
        
        self.window=None
        self.max_num_keys=0
        self.satodime_keys_status= []
        self.satodime_keys_info= []
        
        self.card_event= True # force update at start
        self.card_event_slots=[]
        
        # get apikeys from file
        self.apikeys={}
        if getattr( sys, 'frozen', False ):
            # running in a bundle
            self.pkg_dir= sys._MEIPASS # for pyinstaller
        else :
            # running live
            self.pkg_dir = path.split(path.realpath(__file__))[0]
        apikeys_path= path.join(self.pkg_dir, "api_keys.ini")
        config = ConfigParser()
        if path.isfile(apikeys_path):  
            config.read(apikeys_path)
            if config.has_section('APIKEYS'):
                self.apikeys= config['APIKEYS']
                logger.debug('APIKEYS: '+ str(self.apikeys))
           
    def request(self, request_type, *args):
        logger.debug('Client request: '+ str(request_type))
        
        method_to_call = getattr(self.handler, request_type)
        reply = method_to_call(*args)
        return reply 
        
    ########################################
    #                           Setup functions                                 #
    ########################################
    
    def card_init_connect(self):
        logger.debug('In card_init_connect()')
        
        # check setup
        unlock_counter=None
        unlock_secret= None
        card_info={}
        card_info['is_owner']= False
        card_info['is_error']= False
        card_info['error']= 'No error'
        card_info['about']='card info are stored in this dict' # to do!
        while(self.cc.card_present):
            (response, sw1, sw2, d)=self.cc.card_get_status()
            
            # check version
            if (self.cc.card_type=='Satodime'):
                card_info['card_status']= d
                v_supported= SATODIME_PROTOCOL_VERSION 
                v_applet= d["protocol_version"] 
                logger.info(f"Satodime version={v_applet} SatodimeTool supported version= {v_supported}")#debugSatochip
                if (v_supported<v_applet):
                    msg=(('The version of your Satodime is higher than supported by SatodimeTool. You should update SatodimeTool to ensure correct functioning!')+ '\n' 
                                + f'    Satodime version: {d["protocol_major_version"]}.{d["protocol_minor_version"]}' + '\n' 
                                + f'    Supported version: {SATODIME_PROTOCOL_MAJOR_VERSION}.{SATODIME_PROTOCOL_MINOR_VERSION}')
                    self.request('show_error', msg)       
            else:
                msg=(f"{self.cc.card_type} card detected! \nSatodimeTool only supports Satodime cards! \nPlease insert a Satodime")
                self.request('show_error', msg)
                card_info['is_error']= True
                card_info['error']= msg
                return card_info
                
            # START setup device (done only once)
            if  (not self.cc.setup_done):
                # these values are not use, just provided for compatibility with Satochip & SeedKeeper
                pin_0= list(urandom(4));  # RFU #list(values['pin'].encode('utf8'))
                pin_tries_0= 0x05;
                ublk_tries_0= 0x01;
                ublk_0= list(urandom(16));  # RFU
                pin_tries_1= 0x01
                ublk_tries_1= 0x01
                pin_1= list(urandom(16)); # RFU
                ublk_1= list(urandom(16)); # RFU
                secmemsize= 32 #0x0000 # => for satochip - TODO: hardcode value?
                memsize= 0x0000 # RFU
                create_object_ACL= 0x01 # RFU
                create_key_ACL= 0x01 # RFU
                create_pin_ACL= 0x01 # RFU
                
                #setup
                (response, sw1, sw2)=self.cc.card_setup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                        pin_tries_1, ublk_tries_1, pin_1, ublk_1, 
                        secmemsize, memsize, 
                        create_object_ACL, create_key_ACL, create_pin_ACL)
                if sw1==0x90 and sw2==0x00:       
                    logger.info(f"Setup applet response: {response}")
                    unlock_counter= response[0:SIZE_UNLOCK_COUNTER]
                    unlock_secret= response[SIZE_UNLOCK_COUNTER:(SIZE_UNLOCK_COUNTER+SIZE_UNLOCK_SECRET)]
                    card_info['is_owner']= True
                    #self.cc.satodime_set_unlock_counter(unlock_counter)
                    #self.cc.satodime_set_unlock_secret(unlock_secret)
                else:
                    msg= f"Unable to set up applet!  sw12={hex(sw1)} {hex(sw2)}"
                    logger.warning(msg)
                    self.request('show_error', msg)
                    card_info['is_error']= True
                    card_info['error']= msg
                    return card_info
                    #raise RuntimeError('Unable to setup the device with error code:'+hex(sw1)+' '+hex(sw2))
                    
            # get authentikey TODO: only keep authentikey_comp_hex?
            try:
                self.authentikey=self.cc.card_export_authentikey()
                self.authentikey_hex= self.authentikey.get_public_key_bytes(compressed=False).hex()
                self.authentikey_comp_hex= self.authentikey.get_public_key_bytes(compressed=True).hex()
                card_info['authentikey_hex']= self.authentikey_hex
                card_info['authentikey_comp_hex']= self.authentikey_comp_hex
            except Exception as ex:
                logger.warning(repr(ex))
                self.request('show_error', repr(ex))
                card_info['is_error']= True
                card_info['error']= repr(ex)
                return card_info
            
            #card label 
            try:
                (response, sw1, sw2, card_label)= self.cc.card_get_label()
                self.card_label= card_label
                card_info['card_label']= card_label
            except Exception as ex:
                logger.warning(f"Error while getting card label: {str(ex)}")
            
            # get certificate & validation
            try:
                is_authentic, txt_ca, txt_subca, txt_device, txt_error = self.cc.card_verify_authenticity()     
                card_info['is_authentic']= is_authentic
                card_info['cert_ca']= txt_ca
                card_info['cert_subca']= txt_subca
                card_info['cert_device']= txt_device
                card_info['cert_error']= txt_error
                
                # TODO: if card is not authenticated?
                # if is_authentic is False:
                    # event, values= self.handler.dialog_confirm_trust(is_authentic, txt_error)
                    # if event== 'Cancel':
                        # card_info['is_error']= True
                        # card_info['error']= "Unauthenticated card rejected by user"
                        # return card_info
                
            except Exception as ex:
                logger.warning(f"Error while checking card authenticity: {str(ex)}")
                card_info['is_error']= True
                card_info['error']= repr(ex)
                return card_info
            
            # add authentikey to TrustStore
            if self.authentikey_hex in self.truststore:
                #pass
                self.truststore[self.authentikey_hex].update(card_info) # merge up-to-date info with existing data
            else:
                authentikey_bytes= bytes.fromhex(self.authentikey_hex)
                secret= bytes([len(authentikey_bytes)]) + authentikey_bytes
                fingerprint= hashlib.sha256(secret).hexdigest()[0:8]
                #authentikey_comp_hex= self.authentikey.get_public_key_bytes(compressed=True).hex()
                card_info['fingerprint']= fingerprint
                self.truststore[self.authentikey_hex]= card_info #{'card_label':card_label, 'fingerprint':fingerprint, 'authentikey_comp_hex':authentikey_comp_hex}#self.card_label
                self.handler.show_notification('Information: ', f'Authentikey added to TrustStore! \n{self.authentikey_comp_hex}')
            
            # save unlock_secret from config file
            # TODO: check authenticity before!
            if (unlock_secret is not None):
                # todo: improve message!
                msg= ''.join([  "Card setup successfully! \n",
                                        " You are now the legitimate owner of the card \n",
                                        "Only the legitimate owner has full access to the card via the NFC interface"
                                    ])
                self.handler.show_message(msg)
                
                try: 
                    logger.info(f'os.path.dirname: {path.dirname(path.abspath("satodime_tool.ini"))}')
                    logger.info(f'os.path.dirname: {path.dirname(path.abspath(__file__))}')
                    logger.info(f'os.path.abspath: {path.abspath(getcwd())}')
                    config = ConfigParser()
                    if path.isfile('satodime_tool.ini'):  
                        config.read('satodime_tool.ini')
                    if config.has_section(self.authentikey_comp_hex) is False:
                        config.add_section(self.authentikey_comp_hex)
                    config.set(self.authentikey_comp_hex, 'unlock_secret', bytes(unlock_secret).hex())
                    config.set(self.authentikey_comp_hex, 'unlock_counter', bytes(unlock_counter).hex())
                    config.set(self.authentikey_comp_hex, 'is_authentic', str(card_info['is_authentic']))
                    with open('satodime_tool.ini', 'w') as f:
                        config.write(f)
                except Exception as e:
                    logger.warning("Exception while saving authentikey data to config file:  "+ str(e))
                    self.handler.show_error("Exception while saving authentikey data to config file: "+ str(e))
                                
            # recover unlock_secret from file then cache it 
            if path.isfile('satodime_tool.ini'):  
                logger.info(f'os.path.dirname: {path.dirname(path.abspath(__file__))}')
                logger.info(f'os.path.abspath: {path.abspath(getcwd())}')
                config = ConfigParser()
                config.read('satodime_tool.ini')
                if config.has_section(self.authentikey_comp_hex):
                    unlock_secret_hex= config.get(self.authentikey_comp_hex, 'unlock_secret')
                    unlock_counter_hex= config.get(self.authentikey_comp_hex, 'unlock_counter')
                    is_authentic= bool(config.get(self.authentikey_comp_hex, 'is_authentic'))
                    unlock_secret= list(bytes.fromhex(unlock_secret_hex))
                    unlock_counter= list(bytes.fromhex(unlock_counter_hex))
                    self.cc.satodime_set_unlock_counter(unlock_counter)
                    self.cc.satodime_set_unlock_secret(unlock_secret)
                    card_info['is_owner']= True
            # return true if wizard finishes correctly 
            return card_info
        
        # no card present 
        self.satodime_keys_info=[]
        card_info['is_error']= True
        card_info['error']= "No card found. Please insert card"
        return card_info
        
    
    ####################################
    #                 SATODIME                         #      
    ####################################
    
    def get_coin(self, key_slip44_hex:str, apikeys:dict):
        
        # if msb is 0, this means we use testnet
        key_slip44_list= list(bytes.fromhex(key_slip44_hex))
        is_testnet= (key_slip44_list[0] & 0x80) == 0x00
        logger.debug("In get_coin(): is_testnet: "+str(is_testnet))
        # now set msb to 1 to normalize
        key_slip44_list[0] = (key_slip44_list[0]  |  0x80)
        key_slip44_hex= bytes(key_slip44_list).hex()
        logger.debug("In get_coin(): key_slip44_hex: "+key_slip44_hex)
        
        if key_slip44_hex== "80000000":
            coin= Bitcoin(is_testnet, apikeys=apikeys) 
        elif key_slip44_hex== "80000002":
            coin= Litecoin(is_testnet, apikeys=apikeys) 
        elif key_slip44_hex== "80000003":
            coin= Doge(is_testnet, apikeys=apikeys) 
        elif key_slip44_hex== "80000005":
            coin= Dash(is_testnet, apikeys=apikeys) 
        elif key_slip44_hex== "8000003c":
            coin= Ethereum(is_testnet, apikeys=apikeys) 
        elif key_slip44_hex== "8000003d":
            coin= EthereumClassic(is_testnet, apikeys=apikeys) 
        elif key_slip44_hex== "80000089":
            coin= RSK(is_testnet, apikeys=apikeys) 
        elif key_slip44_hex== "80000091":
            coin= BitcoinCash(is_testnet, apikeys=apikeys) # todo: convert to cashaddress?
        elif key_slip44_hex== "80000207":
            coin= BinanceSmartChain(is_testnet, apikeys=apikeys) # todo: convert to cashaddress?
        else:
            coin= Bitcoin(True)  # use BTC testnet by default?
            #raise Exception(f"Unsupported coin with slip44 code {key_slip44_hex}")        
        return coin
    
    def get_balance(self, coin, addr):
        balance=0
        is_error= False
        error=""
        try: 
            logger.debug("GET BALANCE : "+str(addr))
            balance= coin.balance_web(addr)
        except Exception as e:
            is_error= True
            error= str(e)
            balance= f"Unable to recover balance"
            logger.warning("Exception during coin.balance_web request: "+str(e))
        return (balance, is_error, error)
    
    def get_privkey_info(self, key_nbr):
        # if keyslot is unsealed, recover private key
        # todo: only recover privkey if required (=> click more-details)
        privkey_info={}
        if self.satodime_keys_status[key_nbr]== STATE_UNSEALED:
            try: 
                (response, sw1, sw2, entropy_list, privkey_list) = self.cc.satodime_get_privkey(key_nbr)        
                privkey_hex= '0x'+bytes(privkey_list).hex()
                #logger.debug('PRIVKEY:'+privkey_hex) # TODO: remove!
                privkey_info['privkey_hex']= privkey_hex
                privkey_info['privkey']= privkey_list
                entropy_hex= bytes(entropy_list).hex()
                entropy_hex_parts= bytes(entropy_list[0:32]).hex() + '\n' +  bytes(entropy_list[32:64]).hex() + '\n' +  bytes(entropy_list[64:96]).hex()
                privkey_info['entropy_hex']= entropy_hex
                privkey_info['entropy_hex_parts']= entropy_hex_parts
                # WIF:
                key_slip44_hex= self.satodime_keys_info[key_nbr]['key_slip44_hex']
                coin= self.get_coin(key_slip44_hex, self.apikeys)
                use_address_comp= self.satodime_keys_info[key_nbr]['use_address_comp']
                if use_address_comp:    
                    privkey_wif= coin.encode_privkey(privkey_list, 'wif_compressed')
                else:
                    privkey_wif= coin.encode_privkey(privkey_list, 'wif')  
                #logger.debug('PRIVKEY_WIF:'+privkey_wif) # TODO: remove!
                privkey_info['privkey_wif']= privkey_wif
                   
            except Exception as ex:
                privkey_info['privkey_hex']= f"Error: {str(ex)}"
                privkey_info['privkey']= f"Error: {str(ex)}"
                privkey_info['privkey_wif']= f"Error: {str(ex)}"
                privkey_info['entropy_hex']=  f"Error: {str(ex)}"
                privkey_info['entropy_hex_parts']= f"Error: {str(ex)}"
    
        return privkey_info
    
    def backup_privkey(self, key_nbr):
    
        # save privkey data  in config file as backup
        # backup should be done before resetting a key, to avoid losing funds...
        # NOTE: when a key is unsealed, funds should be transfered to another account ASAP!
        try: 
            key_slip44_hex= self.satodime_keys_info[key_nbr]['key_slip44_hex']
            pubkey_hex= self.satodime_keys_info[key_nbr]['pubkey_hex']
            addr= self.satodime_keys_info[key_nbr]['address']
            use_segwit= self.satodime_keys_info[key_nbr]['use_segwit']
            if use_segwit:
                addr_segwit= self.satodime_keys_info[key_nbr]['address_comp_segwit']
            
            privkey_info= self.get_privkey_info(key_nbr)
            privkey_hex= privkey_info['privkey_hex']
            privkey_wif= privkey_info['privkey_wif']
            
            config = ConfigParser()
            if path.isfile('satodime_tool.ini'):  
                config.read('satodime_tool.ini')
            if config.has_section(pubkey_hex) is False:
                config.add_section(pubkey_hex)
            config.set(pubkey_hex, 'slip44', key_slip44_hex)
            config.set(pubkey_hex, 'address', addr)
            if use_segwit: 
                config.set(pubkey_hex, 'address_segwit', addr_segwit)
            config.set(pubkey_hex, 'privkey', privkey_hex)
            config.set(pubkey_hex, 'privkey_wif', privkey_wif)
            with open('satodime_tool.ini', 'w') as f:
                config.write(f)
            return True
            
        except Exception as e:
            logger.warning("Exception while saving privkey data to config file:  "+ str(e))
            self.handler.show_error("Exception while saving privkey data to config file: "+ str(e))
            return False
    
    def main_menu(self):
        logger.debug('In main_menu')
       
        while True:
        
            if (self.card_event):
            
                # get status & check if satodime & check authenticity
                self.card_info= self.card_init_connect()
                  
                # get satodime status
                try:
                    (response, sw1, sw2, satodime_status) = self.cc.satodime_get_status()
                    #self.cc.satodime_set_unlock_counter( satodime_status['unlock_counter'] )
                except CardNotPresentError:
                    #(response, sw1, sw2, max_num_keys, satodime_keys_status)= ([], 0x00, 0x00, 0, [])
                    (response, sw1, sw2, satodime_status)= ([], 0x00, 0x00, {})
                    satodime_status= {'unlock_counter':[], 'max_num_keys':0, 'satodime_keys_status':[]}
                
                self.max_num_keys=satodime_status['max_num_keys']
                self.satodime_keys_status= satodime_status['satodime_keys_status']
                
                # logger.debug(f'In main_menu satodime_keys_info0: {self.satodime_keys_info}')
                # logger.debug(f'In main_menu card_event_slots0: {self.card_event_slots}')
                    
                # get keyslot status for each card
                if self.satodime_keys_info == []: 
                    self.satodime_keys_info= self.max_num_keys*[None]
                    self.card_event_slots= range(self.max_num_keys)
                    
                for key_nbr in self.card_event_slots: #range(self.max_num_keys):
            
                    # get keyslot status
                    try: 
                        (response, sw1, sw2, key_info) = self.cc.satodime_get_keyslot_status(key_nbr)        
                    except CardNotPresentError:
                        (response, sw1, sw2, key_info)= ([], 0x00, 0x00, {})
                    
                    # get pubkey
                    if self.satodime_keys_status[key_nbr] in [STATE_SEALED, STATE_UNSEALED]:
                        try: 
                            (response, sw1, sw2, pubkey_list, pubkey_comp_list) = self.cc.satodime_get_pubkey(key_nbr)        
                            pubkey_hex= bytes(pubkey_list).hex()
                            pubkey_comp_hex= bytes(pubkey_comp_list).hex()
                            key_info['pubkey_hex']= pubkey_hex
                            key_info['pubkey_comp_hex']= pubkey_comp_hex
                            logger.debug('PUBKEY:'+pubkey_hex)
                            logger.debug('PUBKEY_COMP:'+pubkey_comp_hex)
                            
                            # recover address from pubkey
                            key_slip44_hex= key_info['key_slip44_hex']
                            logger.debug('key_slip44_hex:'+key_slip44_hex)
                            try:
                                coin= self.get_coin(key_slip44_hex, self.apikeys)
                                key_info['name']= coin.display_name
                                key_info['symbol']= coin.coin_symbol
                                
                                use_address_comp= coin.use_compressed_addr
                                key_info['use_address_comp']= use_address_comp
                                if use_address_comp:
                                    addr= coin.pubtoaddr(bytes(pubkey_comp_list))
                                    logger.debug('ADDR_COMP:'+addr)
                                else:
                                     addr= coin.pubtoaddr(bytes(pubkey_list))
                                     logger.debug('ADDR:'+addr)
                                if DEBUG: addr= DEBUG_ADDRS[coin.coin_symbol] #TODO DEBUG API
                                key_info['address']= addr
                                key_info['address_weburl']= coin.address_weburl(addr)
                                
                                use_segwit= coin.segwit_supported
                                key_info['use_segwit']= use_segwit
                                if use_segwit:
                                    addr_segwit=  coin.pubtosegwit(bytes(pubkey_comp_list))
                                    key_info['address_comp_segwit']= addr_segwit
                                    key_info['address_comp_segwit_weburl']= coin.address_weburl(addr_segwit)
                                    logger.debug('ADDR_COMP_SEGWIT_BYTES:'+addr_segwit) # todo: check if segwit is supported
                            except Exception as ex:
                                key_info['is_error']= True
                                key_info['error']= str(ex)
                                logger.debug(f'Exception with coin: {str(ex)}')
                            
                            # get balance from addr/addr_comp and addr_segwit
                            balance_total=0
                            (balance, is_error, error)= self.get_balance(coin, addr)
                            if not is_error:
                                balance_total+=balance
                            else:
                                balance= error
                            key_info['balance']=balance
                                
                            if use_segwit:
                                (balance_segwit, is_error_segwit, error_segwit)= self.get_balance(coin, addr_segwit)
                                if not is_error_segwit:
                                    balance_total+=balance_segwit
                                else:
                                    balance_segwit= error_segwit
                                key_info['balance_segwit']=balance_segwit
                           
                            key_info['balance_total']=balance_total
                            
                            # token info
                            if (key_info['is_nft'] or key_info['is_token']):
                                try:
                                    if DEBUG: key_info['key_contract_hex']= DEBUG_CONTRACT[coin.coin_symbol] # TODO DEBUG API
                                    contract=key_info['key_contract_hex']
                                    token_balance= coin.balance_token(addr, contract)
                                    logger.debug(f'token_balance: {str(token_balance)}')# debug
                                    token_info= coin.get_token_info(addr, contract)
                                    token_decimals= int(token_info['decimals'] )
                                    logger.debug(f'token_info: {str(token_info)}')# debug
                                    key_info['token_balance']= token_balance/(10**token_decimals)
                                    key_info['token_symbol']= token_info['symbol']
                                    key_info['token_name']= token_info['name']
                                except Exception as ex:
                                    key_info['token_balance']= "Unable to recover token balance"
                                    key_info['token_symbol']= "?"
                                    key_info['token_name']= "unknown"
                                    key_info['is_error']= True
                                    key_info['error']= str(ex)
                                    logger.debug(f'Exception while getting token info: {str(ex)}')
                                    
                            #satodime_keys_info[key_nbr]= key_info
                        except Exception as ex:
                            (response, sw1, sw2, pubkey_list)= ([], 0x00, 0x00, [])
                            pubkey_hex= f"Error: {str(ex)}"
                            logger.debug(f'Error in satodime_get_pubkey: {str(ex)}')
                    
                    else: # STATE_UNINITIALIZED
                        (pubkey_list, pubkey_comp_list)= None, None
                
                    # update state with gathered info
                    self.satodime_keys_info[key_nbr]= key_info
                
                # update layout
                # logger.debug(f'In main_menu satodime_keys_info2: {self.satodime_keys_info}')
                # logger.debug(f'In main_menu card_event_slots2: {self.card_event_slots}')
                layout = self.handler.make_layout3(self.card_info, self.max_num_keys, self.satodime_keys_status, self.satodime_keys_info)
                window_new = sg.Window('Satodime Tool', layout, icon=self.handler.satochip_icon)#.Finalize() 
                if self.window is not None: self.window.close()
                self.window = window_new            
                
                self.card_event= False
                self.card_event_slots=[] # all slots are up-to-date
                
                #continue
            
            event, values = self.window.read(timeout=200)    
            if event != sg.TIMEOUT_KEY:
                break      
        
        #if window is not None: window.close()  
        #del window
        return event, values
    
    
    def action_menu(self, action, key_nbr):
        
        if action=='seal':
            
            # seal key
            (event, values)= self.handler.dialog_seal(key_nbr)
            if event=='Cancel' or event==None:
                return
                
            entropy_hex= values['entropy'] 
            entropy= list(bytes.fromhex(entropy_hex))
            self.card_event= True # force update of  variables storing state
            self.card_event_slots= [key_nbr]
            (response, sw1, sw2, pubkey_list, pubkey_comp_list)= self.cc.satodime_seal_key(key_nbr, entropy)
            
            # set metadata
            RFU1=0x00
            RFU2=0x00
            key_asset= values.get('list_asset_type', 'Coin')
            key_slip44= values.get('list_slip44', 'BTC') # coin symbol as defined in bip44
            key_contract= values.get('contract_address', '') 
            key_tokenid= values.get('token_id', '') 
            key_data= values.get('metadata', '') 
            
            # convert to list
            use_testnet= values.get('use_testnet', False) 
            key_asset= DIC_CODE_BY_ASSET[key_asset]
            key_slip44= DICT_SLIP44_BY_SYMBOL[key_slip44] # as int value
            if use_testnet:
                key_slip44= (key_slip44 & 0x7FFFFFFF) # set  msb to 0
            key_slip44= list(key_slip44.to_bytes(4, 'big'))
            if key_contract=='':
                key_contract= SIZE_CONTRACT*[0x00]
            else:
                key_contract= list(bytes.fromhex(key_contract))
                key_contract=[0, len(key_contract)] + key_contract + (SIZE_CONTRACT-2-len(key_contract))*[0x00]
            if key_tokenid=='':
                key_tokenid= SIZE_TOKENID*[0x00]
            else:
                token_id_int= int(key_tokenid, 10) # check if correct dec
                token_id_bytes= token_id_int.to_bytes(SIZE_TOKENID-2, 'big') # OverflowError thrown if too big
                token_id_bytes= token_id_bytes.lstrip(b'\x00') # trim leading null bytes
                key_tokenid=[0, len(token_id_bytes)] + list(token_id_bytes) +  (SIZE_TOKENID-2-len(token_id_bytes))*[0x00]
            (response, sw1, sw2)= self.cc.satodime_set_keyslot_status_part0(key_nbr, RFU1, RFU2, key_asset, key_slip44, key_contract, key_tokenid)
            
            if key_data=='':
                key_data= SIZE_DATA*[0x00]
            else:
                key_data=list(key_data.encode("utf-8"))
                key_data= [0, len(key_data)] + key_data + (SIZE_DATA-2-len(key_data))*[0x00]
            (response, sw1, sw2)= self.cc.satodime_set_keyslot_status_part1(key_nbr, key_data)
            # TODO notification?
            self.request('show_notification', "Success!", "Key sealed successfully!")
            return
            
        elif action=='unseal':
            
            (event, values)= self.handler.dialog_confirm_unseal(key_nbr)
            if event=='Cancel' or event==None:
                self.request('show_message', f"Operation cancelled by user!")
                return
            if event=='Unseal':
                try:
                    self.card_event= True # force update of  variables storing state
                    self.card_event_slots= [key_nbr]
                    (response, sw1, sw2, entropy_list, privkey_list) = self.cc.satodime_unseal_key(key_nbr)
                    self.request('show_notification', "Success!", "Key unsealed successfully!")
                    #(event, values)= self.handler.dialog_show_unseal(key_nbr, entropy_list, privkey_list)
                except Exception as ex:
                    self.request('show_error', f"Exception during unseal for key {key_nbr}: {str(ex)}")
                return
            else: # should not happen
                return 
        
        elif action=='reset':
            
            (event, values)= self.handler.dialog_confirm_reset(key_nbr)
            if event=='Cancel' or event==None:
                self.request('show_message', f"Operation cancelled by user!")
                return
            if event=='Reset':
            
                # save bckp before reset
                is_backup= self.backup_privkey(key_nbr) #privkey_info= self.get_privkey_info(key_nbr)
                if not is_backup:
                    question= "Failed to backup privkeys to 'satodime_tool.ini'. Are you sure you want to reset this key?"
                    proceed= handler.yes_no_question(question) #True or False
                    if not proceed:
                        return
                
                # reset_key
                try:
                    self.card_event= True # force update of  variables storing state
                    self.card_event_slots= [key_nbr]
                    (response, sw1, sw2) = self.cc.satodime_reset_key(key_nbr)
                    self.request('show_notification', "Success!", "Key reset successfully!")
                except Exception as ex:
                    self.request('show_error', f"Exception during reset for key {key_nbr}: {str(ex)}")
                
                return
            else: # should not happen
                return 
        
        else: # should not happen
            return
            
        
        
            
        
        