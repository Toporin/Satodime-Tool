import PySimpleGUIQt as sg 
import base64 
import json
import getpass
import sys
import os
import logging
import hashlib
import requests
import re
from os import urandom

from pysatochip.JCconstants import *  #JCconstants
from pysatochip.CardConnector import CardConnector
from pysatochip.CardConnector import UninitializedSeedError, SeedKeeperError, UnexpectedSW12Error, CardError, CardNotPresentError
from pysatochip.version import SATODIME_PROTOCOL_MAJOR_VERSION, SATODIME_PROTOCOL_MINOR_VERSION, SATODIME_PROTOCOL_VERSION
from pysatochip.version import PYSATOCHIP_VERSION

#from cryptos import transaction, main #deserialize
#from cryptos.coins import Bitcoin, BitcoinCash, Litecoin

# print("DEBUG START handler.py ")
# print("DEBUG START handler.py __name__: "+__name__)
# print("DEBUG START handler.py __package__: "+str(__package__))

try: 
    from version import SATODIMETOOL_VERSION
except Exception as e:
    print('handler.py importError: '+repr(e))
    from .version import SATODIMETOOL_VERSION
    
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

try: 
    from slip44 import LIST_SLIP44, LIST_SLIP44_TOKEN_SUPPORT
except Exception as e:
    print('handler.py importError: '+repr(e))
    from .slip44 import LIST_SLIP44, LIST_SLIP44_TOKEN_SUPPORT

class HandlerTxt:
    def __init__(self):
        pass

    def update_status(self, isConnected):
        if (isConnected):
            print("Card connected!")
            self.client.card_event=True
        else:
            print("Card disconnected!")

    def show_error(self,msg):
        print("ERROR:" + msg)
    
    def show_success(self, msg):
        print(msg)
        
    def show_message(self, msg):
        print(msg)
    
    def yes_no_question(self, question):
        while "the answer is invalid":
            reply = str(input(question+' (y/n): ')).lower().strip()
            if reply[0] == 'y':
                return True
            if reply[0] == 'n':
                return False
        
    def get_passphrase(self, msg): 
        is_PIN=True
        pin = getpass.getpass(msg) #getpass returns a string
        return (is_PIN, pin)
        
    def QRDialog(self, data, parent=None, title = '', show_text=False, msg= ''):
        print(msg)

class HandlerSimpleGUI:
    def __init__(self, loglevel= logging.WARNING): 
        logger.setLevel(loglevel)
        logger.debug("In __init__")
        sg.theme('BluePurple')
        # absolute path to python package folder of satochip_bridge ("lib")
        #self.pkg_dir = os.path.split(os.path.realpath(__file__))[0] # does not work with packaged .exe 
        if getattr( sys, 'frozen', False ):
            # running in a bundle
            self.pkg_dir= sys._MEIPASS # for pyinstaller
        else :
            # running live
            self.pkg_dir = os.path.split(os.path.realpath(__file__))[0]
        logger.debug("PKGDIR= " + str(self.pkg_dir))
        self.satochip_icon= self.icon_path("satochip.png") #"satochip.png"
        self.satochip_unpaired_icon= self.icon_path("satochip_unpaired.png") #"satochip_unpaired.png"
        
        self.tray = sg.SystemTray(filename=self.satochip_icon) 
         
         
    def icon_path(self, icon_basename):
        #return resource_path(icon_basename)
        return os.path.join(self.pkg_dir, icon_basename)
    
    # CAUTION: update_status is called from another thread and in principle, no gui is allowed outside of the main thread
    def update_status(self, isConnected):
        logger.debug('In update_status')
        self.client.card_event=True #trigger update of GUI 
         
    def show_error(self, msg):
        sg.popup('Error!', msg, icon=self.satochip_unpaired_icon)
    def show_success(self, msg):
        sg.popup('Success!', msg, icon=self.satochip_icon)
    def show_message(self, msg):
        sg.popup('Notification', msg, icon=self.satochip_icon)
    def show_notification(self, title, msg):
        #logger.debug("START show_notification")
        self.tray.ShowMessage(title, msg, time=100000)
        
    def approve_action(self, question):
        logger.debug('In approve_action')
        layout = [[sg.Text(question)],    
                        [sg.Checkbox('Skip confirmation for this connection (not recommended)', key='skip_conf')], 
                        [sg.Button('Yes'), sg.Button('No')]]   
        window = sg.Window('Confirmation required', layout, icon=self.satochip_icon)  #ok
        event, values = window.read()    
        window.close()  
        del window
        return (event, values)
        
    def yes_no_question(self, question):
        logger.debug('In yes_no_question')
        layout = [[sg.Text(question)],      
                        [sg.Button('Yes'), sg.Button('No')]]      
        window = sg.Window('Confirmation required', layout, icon=self.satochip_icon)  #ok
        #window = sg.Window('Confirmation required', layout, icon="satochip.ico")    #ok
        event, values = window.read()    
        window.close()  
        del window
        
        if event=='Yes':
            return True
        else: # 'No' or None
            return False
                
    def get_passphrase(self, msg): 
        logger.debug('In get_passphrase')
        layout = [[sg.Text(msg)],      
                         [sg.InputText(password_char='*', key='pin')],      
                         [sg.Submit(), sg.Cancel()]]      
        window = sg.Window('PIN required', layout, icon=self.satochip_icon)    
        event, values = window.read()    
        window.close()
        del window
        
        is_PIN= True if event=='Submit' else False 
        pin = values['pin']

        return (is_PIN, pin)
    
    def get_data(self, msg): 
        logger.debug('In get_data')
        layout = [[sg.Text(msg)],      
                         [sg.InputText(key='data')],      
                         [sg.Submit(), sg.Cancel()]]      
        window = sg.Window('SeedKeeper', layout, icon=self.satochip_icon)    
        event, values = window.read()    
        window.close()
        del window
        
        is_data= True if event=='Submit' else False 
        data = values['data']
        return (is_data, data)
     
    def QRDialog(self, data, title = "SatodimeTool: QR code", msg= ''):
        logger.debug('In QRDialog')
        import pyqrcode
        code = pyqrcode.create(data)
        image_as_str = code.png_as_base64_str(scale=5, quiet_zone=2) #string
        image_as_str= base64.b64decode(image_as_str) #bytes
        
        layout = [[sg.Image(data=image_as_str, tooltip=None, visible=True)],
                        [sg.Text(msg)],
                        [sg.Button('Ok'), sg.Button('Cancel')]]     
        window = sg.Window(title, layout, icon=self.satochip_icon)    
        event, values = window.read()        
        window.close()
        del window
        return (event, values) 
     
    def setup_card(self):
        logger.debug('In setup_card')
        layout = [
                        #[sg.Text(f'Your {self.client.cc.card_type} needs to be set up! This mùust be done only once.')],      
                        [sg.Text(f'Please take a moment to set up your {self.client.cc.card_type}. This must be done only once.')],      
                        [sg.Text('Enter new PIN: ', size=(16,1)), sg.InputText(password_char='*', key='pin')],      
                        [sg.Text('Confirm PIN: ', size=(16,1)), sg.InputText(password_char='*', key='pin2')],      
                        [sg.Text('Enter card label (optional): ', size=(16,1)), sg.InputText(key='card_label')],      
                        [sg.Text(size=(40,1), key='-OUTPUT-', text_color='red')],
                        [sg.Submit(), sg.Cancel()]]     
                        
        window = sg.Window('Setup new card', layout, icon=self.satochip_icon)    
        while True:                             
            event, values = window.read() 
            if event == None or event == 'Cancel':
                break      
            elif event == 'Submit':    
                try:
                    pin= values['pin']
                    pin2= values['pin2']
                    if pin != pin2:
                        raise ValueError("WARNING: the PIN values do not match! Please type PIN again!")
                    elif len(pin) < 4:
                        raise ValueError("WARNING: the PIN must have at least 4 characters!")
                    elif len(pin) > 16:
                        raise ValueError("WARNING: the PIN must have less than 16 characters!") 
                    label= values['card_label']
                    if len(label)>64:
                        raise ValueError(f"WARNING: label must have less than 64 characters! Choose another label.")
                    break
                except ValueError as ex: # wrong hex value
                    window['-OUTPUT-'].update(str(ex)) 
                
        window.close()
        del window
        return event, values
        
    def edit_card_label(self, old_label):    
        logger.debug("edit_card_label")
        
        layout = [
            [sg.Text(f'Enter a new label for you card (max {MAX_CARD_LABEL_SIZE} chars): ', size=(45, 1))],
            [sg.Text('Label: ', size=(10, 1)), sg.InputText(default_text= old_label, key='label', size=(64, 1))],
            [sg.Text(size=(40,1), key='-OUTPUT-')],
            [sg.Submit(), sg.Cancel()],
        ] 
        window = sg.Window('SatodimeTool: edit card label', layout, icon=self.satochip_icon)  #ok
        #event, values=None, None
        while True:                             
            event, values = window.read() 
            if event == None or event == 'Cancel':
                break      
            elif event == 'Submit':    
                try:
                    new_label= values['label']
                    new_label_size= len(new_label.encode('utf-8'))
                    if new_label_size > MAX_CARD_LABEL_SIZE:
                        raise ValueError(f"Wrong label length: {len(new_label_size)} is higher than maximum allowed of {MAX_CARD_LABEL_SIZE}")
                    break
                except ValueError as ex: # wrong hex value
                    window['-OUTPUT-'].update(str(ex)) #update('Error: seed should be an hex string with the correct length!')
                
        window.close()
        del window
        return event, values
        
    ####################################
    #                                ABOUT                                 #      
    ####################################
    
    def about_menu(self):
    
        logger.debug('In about_menu')
        msg_copyright= ''.join([ '(c)2021 - Satodime by Toporin - https://github.com/Toporin/ \n',
                                                        "This program is licensed under the GNU Lesser General Public License v3.0 \n",
                                                        "This software is provided 'as-is', without any express or implied warranty.\n",
                                                        "In no event will the authors be held liable for any damages arising from \n"
                                                        "the use of this software."])
        #sw version
        v_supported_satodime= SATODIME_PROTOCOL_VERSION
        sw_rel_satodime= str(SATODIME_PROTOCOL_MAJOR_VERSION) +'.'+ str(SATODIME_PROTOCOL_MINOR_VERSION)
        fw_rel= "N/A"
        is_seeded= "N/A"
        needs_2FA= "N/A"
        needs_SC= "N/A"
        authentikey= None
        authentikey_comp= "N/A"
        card_label= "N/A"
        #msg_status= ("Card is not initialized! \nClick on 'Setup new Satochip' in the menu to start configuration.")
         
        if (self.client.cc.card_present):
            (response, sw1, sw2, status)=self.client.cc.card_get_status()
            if (sw1==0x90 and sw2==0x00):
                #hw version
                v_applet= (status["protocol_major_version"]<<8)+status["protocol_minor_version"] 
                fw_rel= str(status["protocol_major_version"]) +'.'+ str(status["protocol_minor_version"])  +' - '+ str(status["applet_major_version"]) +'.'+ str(status["applet_minor_version"])
                # status
                if (self.client.cc.card_type=='Satodime' and v_supported_satodime<v_applet):
                    msg_status=(f'The version of your Satodime is higher than supported. \nYou should update SatodimeTool!')
                elif (self.client.cc.card_type!='Satodime'):
                    msg_status=(f"{self.client.cc.card_type} card detected! \nSatodimeTool only supports Satodime cards! \nPlease insert a Satodime")
                else:
                    msg_status= 'SatodimeTool is up-to-date'
                # needs2FA?
                if len(response)>=9 and response[8]==0X01: 
                    needs_2FA= "yes"
                elif len(response)>=9 and response[8]==0X00: 
                    needs_2FA= "no"
                else:
                    needs_2FA= "unknown"
                #is_seeded?
                if len(response) >=10:
                    is_seeded="yes" if status["is_seeded"] else "no" 
                else: #for earlier versions
                    try: 
                        self.client.cc.card_bip32_get_authentikey()
                        is_seeded="yes"
                    except UninitializedSeedError:
                        is_seeded="no"
                    except Exception:
                        is_seeded="unknown"    
                # secure channel
                if status["needs_secure_channel"]:
                    needs_SC= "yes"
                else:
                    needs_SC= "no"
                # authentikey
                try:
                    authentikey_pubkey= self.client.cc.card_export_authentikey() # self.client.authentikey #
                    authentikey_bytes= authentikey_pubkey.get_public_key_bytes(compressed=False)
                    authentikey= authentikey_bytes.hex()
                    authentikey_comp= authentikey_pubkey.get_public_key_bytes(compressed=True).hex()
                except UninitializedSeedError:
                    authentikey= None
                    authentikey_comp= "This SeedKeeper is not initialized!"
                except UnexpectedSW12Error as ex:
                    authentikey= None
                    authentikey_comp= str(ex)
                    #self.show_error(str(ex))
                #card label 
                try:
                    (response, sw1, sw2, card_label)= self.client.cc.card_get_label()
                except Exception as ex:
                    card_label= str(ex)
            else: 
                msg_status= f'Unexpected error while polling card: error code {hex(sw1)} {hex(sw2)}'
        else:
            msg_status= 'No card found! please insert card!'
            
        frame_layout1= [ [sg.Text('Card label: ', size=(20, 1)), sg.Text(card_label, key='card_label')],
                                        [sg.Text('Firmware version: ', size=(20, 1)), sg.Text(fw_rel)],
                                        [sg.Text('Uses Secure Channel: ', size=(20, 1)), sg.Text(needs_SC)],
                                        [sg.Text('Authentikey: ', size=(20, 1)), sg.Text(authentikey_comp)],
                                        [sg.Button('Show TrustStore', key='show_truststore', size= (20,1) ),  
                                            sg.Button('Verify Card', key='verify_card', size= (20,1) ),
                                             sg.Button('Edit label', key='edit_label', size= (20,1) ) ]
                                     ]
        frame_layout2= [
                                    [sg.Text('Supported version (Satodime): ', size=(20, 1)), sg.Text(sw_rel_satodime)],
                                    [sg.Text('SatodimeTool version: ', size=(20, 1)), sg.Text(SATODIMETOOL_VERSION)],
                                    [sg.Text('Pysatochip version: ', size=(20, 1)), sg.Text(PYSATOCHIP_VERSION)],
                                    [sg.Text(msg_status, justification='center', relief=sg.RELIEF_SUNKEN)]]
        frame_layout3= [[sg.Text(msg_copyright, justification='center', relief=sg.RELIEF_SUNKEN)]]
        layout = [[sg.Frame(self.client.cc.card_type, frame_layout1, font='Any 12', title_color='blue')],
                      [sg.Frame('SatodimeTool status', frame_layout2, font='Any 12', title_color='blue')],
                      [sg.Frame('About SatodimeTool', frame_layout3, font='Any 12', title_color='blue')],
                      [sg.Button('Ok')]]
        
        window = sg.Window('SatodimeTool: About', layout, icon=self.satochip_icon)    
        
        while True:
            event, values = window.read() 
            if event== 'show_truststore':
                headings=['Fingerprint', 'Card label', 'Authentikey']
                truststore_list=[]
                for authentikey, dic_info in self.client.truststore.items():
                    fingerprint= dic_info['fingerprint']
                    card_label= dic_info['card_label']
                    authentikey_comp_hex= dic_info['authentikey_comp_hex']
                    truststore_list.append([fingerprint, card_label, authentikey_comp_hex])
                if len(truststore_list)>0:
                    layout2 = [
                          [sg.Table(truststore_list, headings=headings, auto_size_columns=False, col_widths=[10, 25, 65] )], #todo: could not manage to set column size
                          [sg.Button('Ok')],
                        ]
                else:
                    layout2 = [
                          [sg.Text('TrustStore is empty!', size=(20, 1))],
                          [sg.Button('Ok')],
                        ]
                window2 = sg.Window('SatodimeTool TrustStore', layout2, icon=self.satochip_icon, finalize=True)  #ok
                event2, values2 = window2.read()    
                window2.close()  
                del window2
                
            elif event== 'edit_label':
                event2, values2= self.edit_card_label(card_label)
                new_label= values2['label']
                try:
                    (response, sw1, sw2)= self.client.cc.card_set_label(new_label)
                    window['card_label'].update(new_label)      
                except Exception as ex:
                    logger.warning("Exception while changing card label "+str(ex))
                pass
                
            elif event== 'verify_card':
                card_info= self.client.truststore[self.client.authentikey_hex]
                self.show_card_authenticity(card_info)
            
            elif event=='Ok' or event=='Cancel' or event==None:
                break
        
        window.close()  
        del window
    
    def show_card_authenticity(self, card_info):
        
        is_authentic= card_info['is_authentic']
        cert_ca= card_info['cert_ca']
        cert_subca= card_info['cert_subca']
        cert_device= card_info['cert_device']
        cert_error=  card_info['cert_error']
        if is_authentic:
            txt_result= 'Device authenticated successfully!'
            txt_color= 'green'
        else:
            txt_result= ''.join(['Error: could not authenticate the issuer of this card! \n', 
                                        'Reason: ', cert_error , '\n\n',
                                        'If you did not load the card yourself, be extremely careful! \n',
                                        'Contact support(at)satochip.io to report a suspicious device.'])
            txt_color= 'red'
        
        text_cert_chain= 32*"="+" Root CA certificate: "+32*"="+"\n"
        text_cert_chain+= cert_ca
        text_cert_chain+= "\n"+32*"="+" Sub CA certificate: "+32*"="+"\n"
        text_cert_chain+= cert_subca
        text_cert_chain+= "\n"+32*"="+" Device certificate: "+32*"="+"\n"
        text_cert_chain+= cert_device
        
        layout2 = [
                  [sg.Text(txt_result, text_color= txt_color)],
                  [sg.Multiline(text_cert_chain, key='text_cert_chain', size=(80,20), visible=True)],
                  [sg.Button('Ok')],
                ]
        window2 = sg.Window('SatodimeTool certificate chain validation', layout2, icon=self.satochip_icon, finalize=True)  #ok
        event2, values2 = window2.read()    
        window2.close()  
        del window2
    
    def help_menu(self):
        logger.debug('In help_menu')
        path = os.path.join(self.pkg_dir, 'help/English.txt')
        with open(path, 'r', encoding='utf-8') as f:
            help_txt = f.read().strip()
        
        languages=['English', 'Français']
        layout = [
            [sg.Text('Select language: ', size=(15, 1)), sg.InputCombo(languages, key='lang', size=(25, 1), enable_events=True)],
            [sg.Multiline(help_txt, key='help_txt', size=(60,20), visible=True)],
            [sg.Button('Ok')]
        ]
        window = sg.Window("Help manual", layout, icon=self.satochip_icon).finalize()
        while True:
            event, values = window.read()  
            if event=='Ok' or event=='Cancel' or event==None:
                break
            if event== 'lang':
                path = os.path.join(self.pkg_dir, 'help/'+values['lang']+'.txt')
                with open(path, 'r', encoding='utf-8') as f:
                    help_txt = f.read().strip()
                window['help_txt'].update(help_txt)
            
        window.close()  
        del window
        
    ####################################
    #                              SATODIME                            #      
    ####################################
        
    def make_layout3(self, card_info, max_num_keys, satodime_keys_status, satodime_keys_info):
        
        buttons= [ ('Black', 'Grey'), ('Black', 'Green'), ('Black', 'orange') ]
        colors=['Grey', 'LightGreen', '#FFD580']  # #FFD580 is light orange
        size_txt= 12
        
        layout= []
        #layout.append( [sg.Text('Welcome to Satodime Tool !')] )
        
        # check card 
        is_error= card_info['is_error']
        if is_error:
            color_valid= 'Red'
            txt_valid= card_info['error']
            frame_card_info= [[ sg.Text('Card status:', background_color= color_valid), sg.Text(txt_valid, background_color= color_valid), ]]
        else:
            # card info
            is_owner= card_info["is_owner"]
            if is_owner:
                txt_owner= "You are the card owner"
            else:
                txt_owner= "You are NOT the card owner"
            is_authentic= card_info['is_authentic']
            if is_authentic:
                color_valid= 'LightBlue' 
                txt_valid= 'This is an authentic Satodime!'
            else: 
                color_valid= 'Red'
                txt_valid=  'WARNING: there is an issue with this Satodime! '
            frame_card_info= [ [    sg.Text('Card status:', size=(size_txt, 1), background_color= color_valid), sg.Text(txt_valid, background_color= color_valid),],
                                                [    sg.Text('Card owner:', size=(size_txt, 1), background_color= color_valid), sg.Text(txt_owner, background_color= color_valid),],
                                                [   sg.Button('Details', disabled= False, key='show_card_authenticity'),
                                                    sg.Button('Refresh', disabled= False, key='refresh_card_info'),
                                                    sg.Button('Transfer card', disabled= False, key='transfer_card') ] 
                                            ]
        layout.append( [sg.Frame('Card info', frame_card_info, background_color='LightBlue', key='frame_card_info',  font='Any 12')] )
        
        # key status for each key
        for key_nbr in range(max_num_keys):
            
            #label= "Key #"+ str(key_nbr)
            
            # get keyslot status for key
            key_info= satodime_keys_info[key_nbr]
            
            # parse metadata
            key_status= key_info['key_status']
            key_status_txt= key_info['key_status_txt']
            
            frame_layout=[]
            color= colors[key_status]
            if key_status== STATE_UNINITIALIZED:
                pubkey_hex= '(none)'
                address= '(none)'
                privkey_hex= '(none)'
                
                frame_layout+= [ [sg.Text('Status: ', size=(size_txt, 1), background_color=color), sg.Text(key_status_txt, background_color=color)],
                                                [ sg.Button('Seal key!', disabled= False, key='action_seal_'+str(key_nbr)),
                                                   sg.Button('More details', disabled= False, key='show_details_'+str(key_nbr)) ]
                                                ]
                                                
            elif key_status== STATE_SEALED or key_status== STATE_UNSEALED:
                
                coin_pubkey_hex= key_info['pubkey_comp_hex']
                logger.debug('PUBKEY:'+coin_pubkey_hex)
                coin_address= key_info['address'] #key_info['address_comp']  if key_info['use_address_comp'] else  key_info['address'] # for example eth use uncompressed addr
                logger.debug('ADDRESS:'+coin_address)
                coin_name= key_info['name']
                coin_symbol= key_info['symbol']
                coin_balance= key_info['balance_total']
                coin_info= f"{coin_balance} {coin_name} ({coin_symbol})"
                
                # coin info                
                frame_layout+= [ #[sg.Text('Status: ', size=(size_txt, 1), background_color=color), sg.Text(key_status_txt, background_color=color)],                                               
                                                [sg.Text('Address: ', size=(size_txt, 1), background_color=color), sg.Text(coin_address, background_color=color)],
                                                [sg.Text('Balance: ', size=(size_txt, 1), background_color=color), sg.Text(coin_info, background_color=color)],
                                            ]
                
                is_token= key_info['is_token']
                is_nft= key_info['is_nft']
                
                # token info if any
                if is_token or is_nft:
                    token_balance= key_info['token_balance']
                    token_symbol= key_info['token_symbol']
                    token_name= key_info['token_name']
                    token_info= f"{token_balance} {token_name} ({token_symbol})"
                    token_txt= 'Token balance: ' if is_token else 'NFT balance: '
                    frame_layout+= [[sg.Text(token_txt, size=(size_txt, 1), background_color=color), sg.Text(token_info, background_color=color)],
                                            ]
                if is_nft:
                    token_id= 'TODO'
                    # # todo: get token_id
                
                if key_status== STATE_SEALED: 
                    frame_layout+= [[ sg.Button('Unseal key!', disabled= False, key='action_unseal_'+str(key_nbr)), 
                                                        sg.Button('More details', disabled= False, key='show_details_'+str(key_nbr)) ]]
                else: # key_status== STATE_UNSEALED: 
                    frame_layout+= [[sg.Button('Reset key!', disabled= False, key='action_reset_'+str(key_nbr)),
                                                    sg.Button('More details', disabled= False, key='show_details_'+str(key_nbr)) ]]
                    
            else: # should not happen!
                #status= "UNKNOWN!"
                frame_layout+= [ [sg.Text('Status: ', size=(size_txt, 1)), sg.Text(key_status_txt)]]
                
            label= "Key #"+ str(key_nbr) + " " + key_status_txt
            layout.append( [sg.Frame(label, frame_layout, background_color=color, key='frame '+label, font='Any 12')] )
        
        # add menu
        layout.append( [sg.Button('About', disabled= False, key='about'), 
                                sg.Button('Help', disabled= False, key='help'), 
                                sg.Button('Quit', disabled= False, key='quit')] )
        
        return layout

    def dialog_seal(self, key_nbr):
        
        LIST_ASSET_LIMITED= ['Coin'] 
        LIST_ASSET_PARTIAL= ['Coin', 'Token'] 
        LIST_ASSET_FULL= ['Coin', 'Token', 'NFT'] 
        use_metadata=False
        layout = [
            [sg.Text('Coin type: ', size=(12, 1), visible=True), 
                sg.InputCombo(LIST_SLIP44, default_value='BTC', key='list_slip44', enable_events=True, size=(40, 1)),  
                sg.Checkbox('use testnet', key='use_testnet', default=False)],
            
            [sg.Text('Asset type: ', size=(12, 1)), sg.InputCombo(LIST_ASSET_LIMITED, default_value='Coin', key='list_asset_type', enable_events=True, size=(40, 1)) ],
            
            [sg.Text('', size=(12, 1), key='txt_contract', enable_events=True, visible=False), sg.InputText(key='contract_address', size=(68, 1), enable_events=True, visible=False)],
            [sg.Text('', size=(12, 1), key='txt_tokenid', enable_events=True, visible=False), sg.InputText(key='token_id', size=(68, 1), enable_events=True, visible=False)],
            
            # TODO: generate random entropy
            [sg.Text('Entropy input: ', size=(12, 1)), sg.InputText(key='entropy', size=(50, 1), enable_events=True), sg.Button('Generate randomly', key='generate_random')],
            [sg.Text('Entropy output: ', size=(12, 1)), sg.Text(64*'0', key='entropy_out', size=(50, 1)), ],
            #[sg.Text('Enter entropy as a 64-hex string: ', size=(40, 1)), sg.Button('Generate randomly', key='generate_random')],
            #[sg.Text('Hex value: ', size=(12, 1)), sg.InputText(key='entropy', size=(68, 1))],
            
            #[sg.Checkbox('Use additional metadata', key='use_metadata', default=use_metadata, enable_events=True)], 
            #[sg.Text('', size=(12, 1), key='metadata_prompt', visible=use_metadata), sg.InputText(key='metadata', visible=use_metadata)], 

            [sg.Button('Seal', bind_return_key=True), sg.Cancel() ], 
            [sg.Text('', size=(68,1), key='on_error', text_color='red')],
        ] 
        
        window = sg.Window(f'SatodimeTool: seal keyslot # {str(key_nbr)}', layout, icon=self.satochip_icon) 
        while True:                             
            event, values = window.read() 
            if event == None or event == 'Cancel':
                break      
            
            elif event == 'Seal':    
                try:
                    #check entropy: entropy can be any UTF-8 sequence, if more than 32 bytes, it is sha256()
                    entropy_str= values['entropy']
                    entropy_bytes= entropy_str.encode("utf-8")
                    if len(entropy_bytes)>32:
                        entropy_bytes= hashlib.sha256(entropy_bytes).digest()
                    entropy_hex= entropy_bytes.hex()
                    entropy_hex= entropy_hex + (64-len(entropy_hex))*'0'
                    values['entropy']= entropy_hex
                    # check contract (hex value)
                    contract= values['contract_address']
                    contract_bytes= self.checkContractFieldToBytes(contract, slip44) # raise if ill-formatted
                    values['contract_address_bytes']= contract_bytes
                    # if contract !='':
                        # int(contract, 16) # check if correct hex
                        # contract= contract[contract.startswith("0x") and len("0x"):] #strip '0x' if need be
                        # contract= contract[contract.startswith("0X") and len("0X"):] #strip '0x' if need be
                        # bytes.fromhex(contract) # hex must also contain even number of chars
                        # if len(contract) > 64: #TODO: check according to coin
                            # raise ValueError(f"Wrong contract length: {len(entropy)} (should be max 64 hex characters)") 
                        # values['contract_address']= contract
                    
                    # check tokenid (numeric value)
                    token_id= values['token_id']
                    if token_id != '':
                        token_id_int= int(token_id, 10) # check if correct dec
                        token_id_bytes= token_id_int.to_bytes(SIZE_TOKENID-2, 'big') # OverflowError thrown if too big
                    # todo: check  data
                    # metadata= values['metadata']
                    # metadata_bytes= metadata.encode("utf-8")
                    # if len(metadata_bytes)>(SIZE_DATA-2):
                        # raise ValueError(f"Wrong metadata length: {len(metadata_bytes)} (should be maximum 64 bytes)")
                    # if checks are ok, get out of loop
                    break
                except ValueError as ex: # wrong hex value
                    window['on_error'].update(str(ex)) #update('Error: seed should be an hex string with the correct length!')
            
            elif event == 'list_slip44':
                slip44= values['list_slip44']
                if slip44 in LIST_SLIP44_TOKEN_SUPPORT:
                    window['list_asset_type'].update(value='', values=LIST_ASSET_FULL)
                elif slip44=='XCP':
                    window['list_asset_type'].update(value='', values=LIST_ASSET_PARTIAL)
                    window['token_id'].update(visible=False)
                    window['token_id'].update('')
                    window['txt_tokenid'].update(visible=False) 
                    window['txt_contract'].update("Asset name: ") 
                else:
                    window['list_asset_type'].update(value='', values=LIST_ASSET_LIMITED)
                    window['contract_address'].update(visible=False)
                    window['contract_address'].update('')
                    window['token_id'].update(visible=False)
                    window['token_id'].update('')
                    window['txt_contract'].update(visible=False) 
                    window['txt_tokenid'].update(visible=False) 
            
            elif event == 'list_asset_type':    
                asset= values['list_asset_type']
                if asset=='Coin':
                    window['contract_address'].update(visible=False)
                    window['contract_address'].update('')
                    window['token_id'].update(visible=False)
                    window['token_id'].update('')
                    window['txt_contract'].update(visible=False) 
                    window['txt_tokenid'].update(visible=False) 
                else:
                    window['txt_contract'].update('Contract address: ')
                    window['txt_contract'].update(visible=True)
                    window['contract_address'].update(visible=True)
                if asset in ['NFT', 'ERC721', 'BEP721']: 
                    window['txt_contract'].update('Contract address: ')
                    window['txt_contract'].update(visible=True) 
                    window['contract_address'].update(visible=True)
                    window['txt_tokenid'].update('TokenID: ')
                    window['txt_tokenid'].update(visible=True) 
                    window['token_id'].update(visible=True)
                if asset in ['Token', 'ERC20', 'BEP20']: 
                    window['txt_contract'].update('Contract address: ')
                    window['txt_contract'].update(visible=True) 
                    window['contract_address'].update(visible=True)
                    window['txt_tokenid'].update('')
                    window['txt_tokenid'].update(visible=False) 
                    window['token_id'].update(visible=False)
                if asset in ['ERC20', 'ERC721']:
                    window['list_slip44'].update(value='ETH')
                if asset in ['BEP20', 'BEP721']: 
                    window['list_slip44'].update(value='BSC')
                
            # elif event=='use_metadata':
                # use_metadata= not use_metadata 
                # window['metadata_prompt'].update('Enter metadata: ')
                # window['metadata_prompt'].update(visible=use_metadata)
                # window['metadata'].update(visible=use_metadata)
                # if not use_metadata:
                    # window['metadata'].update('')
            
            elif event=='generate_random':
                entropy= urandom(32).hex()
                window['entropy'].update(value= entropy)
            
            elif event=='entropy':
                entropy_str= values['entropy']
                entropy_bytes= entropy_str.encode("utf-8")
                if len(entropy_bytes)>32:
                    entropy_bytes= hashlib.sha256(entropy_bytes).digest()
                entropy_hex= entropy_bytes.hex()
                entropy_hex= entropy_hex + (64-len(entropy_hex))*'0'
                window['entropy_out'].update(value= entropy_hex)
            
        window.close()
        del window
        
        return event, values
    
    def checkContractFieldToBytes(self, contract, slip44):
        if contract =='':
            return b''
    
        if slip44 in ['ETH', 'ETC', 'BSC']:
            int(contract, 16) # check if correct hex
            contract= contract[contract.startswith("0x") and len("0x"):] #strip '0x' if need be
            contract= contract[contract.startswith("0X") and len("0X"):] #strip '0x' if need be
            bytes.fromhex(contract) # hex must also contain even number of chars
            if len(contract) > 40:
                raise ValueError(f"Wrong contract length: {len(contract)} (should be 40 hex characters)") 
            contract_bytes= bytes.fromhex(contract)
            return contract_bytes
        
        elif slip44=='XCP':
            # https://counterparty.io/docs/protocol_specification/
            asset=contract
            subasset=""
            check= re.match('(?!\.)(?!.*\.$)(?!.*?\.\.)', asset); # contract cannot start, end with '.' or contains consecutive dots # https://stackoverflow.com/questions/40718851/regex-that-does-not-allow-consecutive-dots
            if check is None:
                raise ValueError(f"Wrong asset format: {asset} (asset cannot start or end with dot or contain consecutive dots)") 
            if "." in asset: # contains subasset
                splited= asset.split(".", maxsplit=1)
                asset= splited[0]
                subasset= splited[1]
                minlength=str(1)
                maxlength= str(250- len(asset) -1)
                pattern= "^[a-zA-Z0-9.-_@!]{" + minlength + "," + maxlength + "}$"
                check= re.match(pattern, subasset)
                if check is None:
                    raise ValueError(f"Wrong subasset format: {subasset} (check for length and unauthorized characters)") 
            if asset.startswith('A'): # numeric asset
                nbr_str= contract.removeprefix("A")
                try:
                    nbr= int(nbr_str)
                    if nbr<(26**12+1) or nbr>(256**8):
                         raise ValueError(f"Wrong numeric asset format: {asset} (numeric value outside of bounds)") 
                except Exception as ex:
                    raise ValueError(f"Wrong numeric asset format: {asset} (asset should start with 'A' followed by numeric value)") 
            else:  # named asset
                check= re.match('^[A-Z]{4,12}$', asset)
                if check is None:
                    raise ValueError(f"Wrong named asset format: {asset} (should be 4-12 uppercase Latin characters)") 
            contract_bytes= contract.encode("utf-8")
            if (len(contract_bytes)>32):
                raise ValueError(f"Unfortunately, Satodime supports only asset name smaller than 32 bytes") 
                #todo: use token_id and metadata as additionnal space
            return contract_bytes
            
        else:
            raise ValueError(f"Unsupported blockchain: {slip44}") 
            
    
    
    def dialog_seal_old(self, key_nbr):
        
        #LIST_ASSET= ['Coin', 'Token', 'ERC20', 'BEP20', 'NFT', 'ERC721', 'BEP721'] #
        LIST_ASSET= ['Coin', 'Token', 'ERC20', 'NFT', 'ERC721'] #
        use_metadata=False
        layout = [
            # TODO: generate random entropy
            [sg.Text('Enter entropy as a 64-hex string: ', size=(40, 1)), sg.Button('Generate', key='generate_random')],
            [sg.Text('Hex value: ', size=(12, 1)), sg.InputText(key='entropy', size=(68, 1))],
            
            [sg.Text('Asset type: ', size=(12, 1)), sg.InputCombo(LIST_ASSET, default_value='Coin', key='list_asset_type', enable_events=True, size=(40, 1)) ],
            [sg.Text('Coin type: ', size=(12, 1), visible=True), 
                sg.InputCombo(LIST_SLIP44, default_value='BTC', key='list_slip44', enable_events=True, size=(40, 1)),  
                sg.Checkbox('use testnet', key='use_testnet', default=False)],
            
            [sg.Text('', size=(12, 1), key='txt_contract', enable_events=True, visible=False), sg.InputText(key='contract_address', size=(68, 1), enable_events=True, visible=False)],
            [sg.Text('', size=(12, 1), key='txt_tokenid', enable_events=True, visible=False), sg.InputText(key='token_id', size=(68, 1), enable_events=True, visible=False)],
            
            [sg.Checkbox('Use additional metadata', key='use_metadata', default=use_metadata, enable_events=True)], 
            [sg.Text('', size=(12, 1), key='metadata_prompt', visible=use_metadata), sg.InputText(key='metadata', visible=use_metadata)], 

            [sg.Button('Seal', bind_return_key=True), sg.Cancel() ], # sg.Cancel()
            [sg.Text('', size=(68,1), key='on_error', text_color='red')],
        ] 
        
        window = sg.Window(f'SatodimeTool: seal keyslot # {str(key_nbr)}', layout, icon=self.satochip_icon) 
        while True:                             
            event, values = window.read() 
            if event == None or event == 'Cancel':
                break      
            elif event == 'Seal':    
                try:
                    #check entropy
                    entropy= values['entropy']
                    if entropy == '':
                        raise ValueError(f"Provide 64 hex characters of entropy or click on 'Generate' for random generation")
                    int(entropy, 16) # check if correct hex
                    entropy= entropy[entropy.startswith("0x") and len("0x"):] #strip '0x' if need be
                    entropy= entropy[entropy.startswith("0X") and len("0X"):] #strip '0x' if need be
                    if len(entropy) not in [64]:
                        raise ValueError(f"Wrong entropy length: {len(entropy)} (should be 64 hex characters)")
                    # check contract
                    contract= values['contract_address']
                    if contract !='':
                        int(contract, 16) # check if correct hex
                        contract= contract[contract.startswith("0x") and len("0x"):] #strip '0x' if need be
                        contract= contract[contract.startswith("0X") and len("0X"):] #strip '0x' if need be
                        if len(contract) > 64: #TODO: check according to coin
                            raise ValueError(f"Wrong contract length: {len(entropy)} (should be max 64 hex characters)") 
                        values['contract_address']= contract
                    # check tokenid, data
                    token_id= values['token_id']
                    if token_id != '':
                        int(token_id, 16) # check if correct hex
                        token_id= token_id[token_id.startswith("0x") and len("0x"):] #strip '0x' if need be
                        token_id= token_id[token_id.startswith("0X") and len("0X"):] #strip '0X' if need be
                        if len(token_id) > 64:
                            raise ValueError(f"Wrong tokenId length: {len(token_id)} (should be max 64 hex characters)")
                        values['token_id']= token_id
                    # todo: check  data
                    metadata= values['metadata']
                    metadata_bytes= metadata.encode("utf-8")
                    if len(metadata_bytes)>(SIZE_DATA-2):
                        raise ValueError(f"Wrong metadata length: {len(metadata_bytes)} (should be maximum 64 bytes)")
                    # if checks are ok, get out of loop
                    break
                except ValueError as ex: # wrong hex value
                    window['on_error'].update(str(ex)) #update('Error: seed should be an hex string with the correct length!')
            elif event == 'list_asset_type':    
                asset= values['list_asset_type']
                if asset=='Coin':
                    window['contract_address'].update(visible=False)
                    window['contract_address'].update('')
                    window['token_id'].update(visible=False)
                    window['token_id'].update('')
                    window['txt_contract'].update(visible=False) 
                    window['txt_tokenid'].update(visible=False) 
                else:
                    window['txt_contract'].update('Contract address: ')
                    window['txt_contract'].update(visible=True)
                    window['contract_address'].update(visible=True)
                if asset in ['NFT', 'ERC721', 'BEP721']: 
                    window['txt_contract'].update('Contract address: ')
                    window['txt_contract'].update(visible=True) 
                    window['contract_address'].update(visible=True)
                    window['txt_tokenid'].update('TokenID: ')
                    window['txt_tokenid'].update(visible=True) 
                    window['token_id'].update(visible=True)
                if asset in ['Token', 'ERC20', 'BEP20']: 
                    window['txt_contract'].update('Contract address: ')
                    window['txt_contract'].update(visible=True) 
                    window['contract_address'].update(visible=True)
                    window['txt_tokenid'].update('')
                    window['txt_tokenid'].update(visible=False) 
                    window['token_id'].update(visible=False)
                if asset in ['ERC20', 'ERC721']:
                    window['list_slip44'].update(value='ETH')
                if asset in ['BEP20', 'BEP721']: 
                    window['list_slip44'].update(value='BSC')
                
            elif event=='use_metadata':
                use_metadata= not use_metadata 
                window['metadata_prompt'].update('Enter metadata: ')
                window['metadata_prompt'].update(visible=use_metadata)
                window['metadata'].update(visible=use_metadata)
                if not use_metadata:
                    window['metadata'].update('')
            
            elif event=='generate_random':
                entropy= urandom(32).hex()
                window['entropy'].update(value= entropy)
                
        window.close()
        del window
        
        return event, values
        
    def dialog_confirm_unseal(self, key_nbr):
        
        msg= ''.join( [ "Warning! \n",
                            "This will unseal the corresponding private key. \n", 
                            "Once exposed, this private key should be stored in a safe place. \n",
                            "Click on 'Unseal' to continue, or 'Cancel' to abort. ",])
        
        layout = [
            # TODO: generate random entropy
            [sg.Multiline(msg, key='warning', size=(40, 4), text_color= 'Orange' )],
            [sg.Button('Unseal'), sg.Cancel() ],
        ] 
    
        window = sg.Window(f'SatodimeTool: unseal keyslot # {str(key_nbr)}', layout, icon=self.satochip_icon) 
        event, values = window.read()    
        window.close()  
        del window   
        
        return (event, values)
            
    def dialog_show_unseal(self, key_nbr: int, entropy_list, privkey_list):
        
        privkey_hex= '0x' + bytes(privkey_list).hex()
        #entropy_hex= '0x' + bytes(entropy_list).hex()
        entropy_hex= bytes(entropy_list[0:32]).hex() + '\n' + bytes(entropy_list[32:64]).hex() + '\n' + bytes(entropy_list[64:]).hex() # shown split in 3 parts
        
        layout = [
            [sg.Text('Private key: ', size=(10, 1)), sg.Multiline(privkey_hex, key='privkey', size=(64, 1) )], 
            [sg.Text('Entropy data: ', size=(10, 1)), sg.Multiline(entropy_hex, key='entropy', size=(64, 3) )], 
            [sg.Button('Show QR Code', key='show_qr'), sg.Button('Close')],
        ] 
        
        window = sg.Window(f'SatodimeTool: unseal keyslot # {str(key_nbr)}', layout, icon=self.satochip_icon)      
        while True:
            event, values = window.read()      
            if event=='Close' or event==None:
                break
            elif event=='show_qr':
                self.QRDialog(privkey_hex, title = "SeedKeeperTool: QR code", msg= 'This is the QR code of your private key. \nMake sure to treat it with respect!')
            else:      
                break     
        
        window.close()  
        del window
        return event, values
        
    def dialog_confirm_reset(self, key_nbr):
        
        msg= ''.join( [ "Warning! \n",
                            "This will reset the corresponding private key. \n", 
                            "Once reset, all the corresponding data will be wiped. \n",
                            "Please ensure that you securely saved the private key before proceeding. \n", 
                            "Click on 'Reset' to continue, or 'Cancel' to abort. ",])
        
        layout = [
            # TODO: generate random entropy
            [sg.Multiline(msg, key='warning', size=(64, 5), text_color= 'Orange' )],
            [sg.Button('Reset'), sg.Cancel() ],
        ] 
    
        window = sg.Window(f'SatodimeTool: reset keyslot # {str(key_nbr)}', layout, icon=self.satochip_icon) 
        event, values = window.read()    
        window.close()  
        del window   
        
        return (event, values)
    
    def show_details(self, key_nbr, key_status, key_info):
            
        buttons= [ ('Black', 'Grey'), ('Black', 'Green'), ('Black', 'Orange') ]
        colors=['Grey', 'LightGreen', '#FFD580']
        
        # parse metadata
        key_status= key_info['key_status']
        key_status_txt= key_info['key_status_txt']
        #key_asset= key_info['key_asset']
        key_asset_txt= key_info['key_asset_txt']
        key_slip44_hex= key_info['key_slip44_hex']
        key_data= key_info['key_data'] 
        key_data_txt= key_info['key_data_txt'] 
        is_token= key_info['is_token']
        is_nft= key_info['is_nft']
        
        color= colors[key_status]
        layout= []
        layout.append( [sg.Text(f'Keyslot #{key_nbr}', background_color=color)] )
        
        #frame_key_info=[]
        #frame_coin_info=[]
        #frame_token_info=[]
        #frame_nft_info=[]
        #frame_private_info=[]
        if key_status== STATE_UNINITIALIZED:
            pubkey_hex= '(none)'
            address= '(none)'
            #privkey_hex= '(none)'
            
            frame_key_info= [ [sg.Text('Status: ', size=(20, 1), background_color=color), sg.Text(key_status_txt, background_color=color)],
                                                [sg.Text('Pubkey: ', size=(20, 1), background_color=color), sg.Text(pubkey_hex, background_color=color)],
                                                [sg.Text('Address: ', size=(20, 1), background_color=color), sg.Text(address, background_color=color)],
                                            ]
            #layout.append( [sg.Frame("Keyslot info", frame_key_info, background_color=color, key='frame_key_info')] )
            
        elif key_status== STATE_SEALED or key_status== STATE_UNSEALED:
            
            # todo: get address
            coin_pubkey_hex= key_info['pubkey_comp_hex']
            coin_address= key_info['address'] #key_info['address_comp']  if key_info['use_address_comp'] else  key_info['address'] # for example eth use uncompressed addr
            use_segwit= key_info['use_segwit'] 
            #coin_address_segwit= key_info['address_comp_segwit']  if use_segwit else ""
            coin_address_legacy= key_info['address_legacy']  if use_segwit else ""
            coin_name= key_info['name']
            coin_symbol= key_info['symbol']
            coin_balance= key_info['balance_total']
            coin_data= f"{coin_balance} {coin_name} ({coin_symbol})"
            if use_segwit:
                coin_data+= f"\t[Segwit: {key_info['balance']}  & legacy: {key_info['balance_legacy']}]"
                #coin_data+= f"\t[non-Segwit: {key_info['balance']}  & Saegwit: {key_info['balance_segwit']}]"
                
            # coin info                
            frame_key_info= [ 
                                            [sg.Text('Status: ', size=(20, 1), background_color=color), sg.Text(key_status_txt, background_color=color)],
                                            [sg.Text('Pubkey: ', size=(20, 1), background_color=color), sg.Text(coin_pubkey_hex, background_color=color)],   
                                            [sg.Text('Asset type: ', size=(20, 1), background_color=color), sg.Text(key_asset_txt, background_color=color)],                                            
                                            [sg.Text('Blockchain: ', size=(20, 1), background_color=color), sg.Text(f"{coin_name} ({key_slip44_hex})", background_color=color)],
                                            #[sg.Text('Address: ', size=(20, 1),  enable_events=True, key='weburl1', background_color=color), sg.Multiline(coin_address, size=(64,1)), sg.Button('Show QR Code', key='show_qr_addr')] ,
                                            [sg.Button('Address: ', key='weburl1'), sg.Multiline(coin_address, size=(64,1)), sg.Button('Show QR Code', key='show_qr_addr')] ,
                                            #[sg.Text('Address segwit: ', size=(20, 1), background_color=color), sg.Multiline(coin_address_segwit, size=(64,1)), sg.Button('Show QR Code', key='show_qr_segwit') ] if use_segwit else [],
                                            #[sg.Button('Address segwit: ', key='weburl2'), sg.Multiline(coin_address_segwit, size=(64,1)), sg.Button('Show QR Code', key='show_qr_segwit') ] if use_segwit else [], 
                                            [sg.Button('Legacy (DO NOT USE!): ', key='weburl2'), sg.Multiline(coin_address_legacy + "-DONOTUSE!", size=(64,1)), sg.Button('Show QR Code', key='show_qr_legacy') ] if use_segwit else [], 
                                            [sg.Text('Balance: ', size=(20, 1), background_color=color), sg.Text(coin_data, background_color=color)], 
                                            # [sg.Text('Balance: ', size=(20, 1), background_color=color), sg.Text(coin_data, background_color=color), 
                                                            # sg.Button("Explorer", key='weburl1'), sg.Button("Explorer", key='weburl2')] if use_segwit else 
                                            # [sg.Text('Balance: ', size=(20, 1), background_color=color), sg.Text(coin_data, background_color=color), 
                                                             # sg.Text("", key='weburl3', background_color=color), sg.Button("Explorer", key='weburl1')],         
                                        ]
            #layout.append( [sg.Frame("Coin info", frame_coin_info, background_color=color, key='frame_coin_info')] )
            
            # token info if any
            if is_token:
                key_contract_hex=  key_info['key_contract_hex']
                token_balance= key_info['token_balance']
                token_symbol= key_info['token_symbol']
                token_name= key_info['token_name']
                token_info= f"{token_balance} {token_name} ({token_symbol})"
                frame_token_info= [ [sg.Text('Contract: ', size=(20, 1), background_color=color), sg.Multiline(key_contract_hex, size=(64,1)), sg.Button('Show QR Code', key='show_qr_contract')],
                                                        [sg.Text('Token balance: ', size=(20, 1), background_color=color), sg.Text(token_info, background_color=color)],
                                                    ]
                #layout.append( [sg.Frame("Token info", frame_token_info, background_color=color, key='frame_token_info')] )
                
            if is_nft:
                key_contract_hex=  key_info['key_contract_hex']
                key_tokenid_int= key_info['key_tokenid_int']
                token_balance= key_info['token_balance']
                token_symbol= key_info['token_symbol']
                token_name= key_info['token_name']
                token_info= f"{token_balance} {token_name} ({token_symbol})"
                
                # Rarible info
                nft_info= key_info['nft_info']
                nft_name= nft_info.get('nft_name', '')
                nft_description= nft_info.get('nft_description', '')
                nft_image_url=""
                if "nft_image_large_url" in nft_info:
                    nft_image_url= nft_info.get('nft_image_large_url')
                elif "nft_image_url" in nft_info:
                    nft_image_url= nft_info.get('nft_image_url')
                # nft_image_url= nft_info.get('nft_image_url',"")
                #nft_explorer_link= nft_info.get('nft_explorer_link', '')
                # get image from url
                nft_image_available= False
                try:
                    # response = requests.get(nft_image_url,  stream=True)
                    # response.raw.decode_content = True
                    # if response.status_code == 200:
                        # nft_image_available= True
                        # nft_image_raw = response.raw.read()
                    from PIL import Image
                    from io import BytesIO
                    size = (256, 256)
                    response = requests.get(nft_image_url)
                    if response.status_code == 200:
                        img = Image.open(BytesIO(response.content))
                        img.thumbnail(size)
                        #img.show() #debug open external viewer
                        bio = BytesIO()
                        img.save(bio, format="PNG")
                        nft_image_raw= bio.getvalue()
                        nft_image_available= True
                except Exception as ex:
                    logger.debug(f'Exception while fetching image from url: {nft_image_url}  Exception: {ex}')
                    
                frame_nft_info= [   
                                            #[sg.Button('Contract: ', key='nft_owner_url'), sg.Multiline(key_contract_hex, size=(64,1)), sg.Button('Show QR Code', key='show_qr_contract')],
                                            [sg.Text('Contract: ', size=(20, 1), background_color=color), sg.Multiline(key_contract_hex, size=(64,1)), sg.Button('Show QR Code', key='show_qr_contract')],
                                            #[sg.Button('Token ID: ', key='nft_url'), sg.Multiline(key_tokenid_int, size=(64,1))],
                                            #[sg.Text('Token ID: ', size=(20, 1), background_color=color), sg.Multiline(key_tokenid_int, size=(64,1))],
                                            [sg.Text('Token ID: ', size=(20, 1), background_color=color), sg.Multiline(key_tokenid_int, size=(64,1)), sg.Button('Show NFT in explorer', key='nft_url')],
                                            #[sg.Text('NFT balance: ', size=(20, 1), background_color=color), sg.Text(token_info, background_color=color)],
                                            [sg.Text('NFT balance: ', size=(20, 1), background_color=color), sg.Text(token_info, background_color=color,  size=(64,1)), sg.Button('Show in explorer ', key='nft_owner_url')],
                                            [sg.Text('NFT name: ', size=(20, 1), background_color=color), sg.Text(nft_name, background_color=color)],
                                            [sg.Text('NFT description: ', size=(20, 1), background_color=color), sg.Text(nft_description, background_color=color), sg.Image(data=nft_image_raw, pad=(5,5))] if nft_image_available else
                                                [sg.Text('NFT description: ', size=(20, 1), background_color=color), sg.Text(nft_description, background_color=color)]
                                            #[sg.Image(data=nft_image_raw, pad=(5,5))] if nft_image_available else [],
                                        ]
                #layout.append( [sg.Frame("NFT info", frame_nft_info, background_color=color, key='frame_nft_info')] )
                
            if key_status== STATE_UNSEALED: 
                privkey_hex= key_info['privkey_hex']
                privkey_wif= key_info['privkey_wif']
                entropy_hex= key_info['entropy_hex_parts']
                txt_entropy= ''.join([ 'Note: the private key is derived from the entropy. \n',
                                                    'The private key is the SHA256(entropy). \n',
                                                    'This ensures that the private key was generated randomly.'])
                # add to layout
                frame_private_info= [ [sg.Text('Private key: ', size=(20, 1), background_color=color), 
                                                                    sg.Multiline(privkey_hex, size=(64, 1)),  
                                                                    sg.Button('Show QR Code', key='show_qr_priv') ], 
                                                          [sg.Text('Private key in WIF: ', size=(20, 1), background_color=color), 
                                                                    sg.Multiline(privkey_wif, size=(64, 1)),
                                                                    sg.Button('Show QR Code', key='show_qr_wif') ], 
                                                          [sg.Text('Entropy: ', size=(20, 1), background_color=color), sg.Multiline(entropy_hex, size=(64, 3))],
                                                          [sg.Text('                ', size=(20, 1), background_color=color), sg.Multiline(txt_entropy,  size=(64, 3), background_color=color)],
                                                        ]
                #layout.append( [sg.Frame("Private info", frame_private_info, background_color=color, key='frame_private_info')] )
                
        else: # should not happen!
            #status= "UNKNOWN!"
            frame_error= [ [sg.Text('Unexpected key status: ', size=(20, 1), background_color=color), sg.Text(key_status, background_color=color)]]
            #layout.append( [sg.Frame("Error!", frame_error, background_color=color, key='frame_error')] )
        
        # tabs
        tabs= [[ sg.Tab('Coin info', frame_key_info) ]]
        if is_nft:
            tabs= tabs+ [[sg.Tab('NFT info', frame_nft_info)]]
        if is_token:
            tabs= tabs+ [[sg.Tab('Token info', frame_token_info)]]
        if key_status== STATE_UNSEALED:
            tabs= tabs+ [[sg.Tab('Private info', frame_private_info)]]

        tabgroup= [sg.TabGroup(tabs, tooltip='TIP2')]
        layout.append(tabgroup)
        
        # add menu
        layout.append( [sg.Button('Ok', disabled= False, key='ok')] )
        
        window = sg.Window(f'SatodimeTool: details for keyslot # {str(key_nbr)}', layout, icon=self.satochip_icon, background_color=color)  
        while True:
            event, values = window.read()      
            if event=='Ok' or event==None:
                break
            elif event=='show_qr_priv':
                self.QRDialog(privkey_hex, title = "SatodimeTool: QR code", msg= 'This is the QR code of your hex private key. \nMake sure to treat it with respect!')
            elif event=='show_qr_wif':
                self.QRDialog(privkey_wif, title = "SatodimeTool: QR code", msg= 'This is the QR code of your WIF private key. \nMake sure to treat it with respect!')
            # elif event=='show_qr_segwit':
                # self.QRDialog(coin_address_segwit, title = "SatodimeTool: QR code", msg= 'This is the QR code of your segwit address')
            elif event=='show_qr_legacy':
                self.QRDialog(coin_address_legacy + "-DONOTUSE!", title = "SatodimeTool: QR code", msg= 'This is the QR code of your LEGACY address \nPlease do NOT use - only for backward compatibility')
            elif event=='show_qr_addr':
                self.QRDialog(coin_address, title = "SatodimeTool: QR code", msg= 'This is the QR code of your address')
            elif event=='show_qr_contract':
                self.QRDialog(key_contract_hex, title = "SatodimeTool: QR code", msg= 'This is the QR code of  the token contract')
            elif event=='weburl1':
                import webbrowser
                webbrowser.open(key_info['address_weburl'])
            elif event=='weburl2':
                import webbrowser
                #webbrowser.open(key_info['address_comp_segwit_weburl'])
                webbrowser.open(key_info['address_legacy_weburl'])
            elif event=='nft_url':
                import webbrowser
                webbrowser.open(key_info['nft_url'])
            elif event=='nft_owner_url':
                import webbrowser
                webbrowser.open(key_info['nft_owner_url'])
            else:      
                break     
        
        window.close()  
        del window   
        
        return (event, values)
    
    def dialog_confirm_trust(self, is_authentic, txt_error):
        
        msg= ''.join( [ "Warning!",
                                "The card could not be validated as genuine \n",
                                "Click on 'I trust this card' to continue, or 'Cancel' to abort",])
        layout = [
            [sg.Text(msg, key='warning', size=(64, 5), text_color= 'Orange' )],
            [sg.Multiline(txt_error, key='error', size=(64, 5), text_color= 'Orange' )],
            [sg.Button('I trust this card'), sg.Cancel() ],
        ] 
    
        window = sg.Window(f'SatodimeTool: add new card', layout, icon=self.satochip_icon) 
        event, values = window.read()    
        window.close()  
        del window   
        
        return (event, values)
        
    # print("DEBUG END handler.py ")