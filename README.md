# Satodime-Tool

  Licence: LGPL v3
  Author: Toporin
  Language: Python (>= 3.6)
  Homepage: https://github.com/Toporin/Satodime-Tool

## Introduction

### What is Satodime

[Satodime](https://github.com/Toporin/Satodime-Applet) is a smartcard applet that stores cryptographic keypairs securely in a secure chip (also called Secure Element). 
Each keypair can be associated with a specific address on a blockchain. 

Each keypair is generated inside the secure chip and can be in any one of 3 states at any time:
	- uninitialized: the keypair has not been generated yet
	- sealed: the keypair has been generated securely inside the chip
	- unsealed: the private key has been revealed

Since the private key is generated inside the secure chip, a Satodime bearer can be certain that nobody (including himself) knows the private key until the key is unsealed.
In effect, a Satodime allows to physically transfer cryptocurrencies such as Bitcoin from one person to another, without having to trust the bearer of the Satodime, AS LONG AS THE KEY IS IN THE SEALED STATE.

Depending on the model, from 1 up to 3 keypairs can be stored simultaneously on a single Satodime.

### Satodime-Tool overview

When the SatodimeTool is launched, it actively looks for Satodime cards on all available interfaces.
Once a Satodime card is detected, the SatodimeTool initiates a connections and checks the authenticity of the cards, the results of this check is shown in the main window in the 'card status' field. If an issue arises with the card, more details are provided by clicking on the 'Details' button.

Below the 'Card info' tab, the status and info of each keyslot is provided. Remember that a Satodime can have up to 3 available keyslots, and each keyslot can be in the 'Uninitialized', 'Sealed' or 'Unsealed' state.
If a keyslot is sealed or unsealed, more details are provided by clicking on the 'More details' button for the corresponding slot. Available info includes the asset type, the blockchain used and the balance available for the associated address.

In a newly issued Satodime card, all the keyslots are in the 'Uninitialized' state, which means that the corresponding private keys have not been generated yet. You can seal a keyslot by clicking on the 'Seal' button: a pop-up menu appears which allows to define the characteristics of the generated key, including the type of asset to store (a coin, a token or a NFT), the blockchain used (such as BTC, ETH,...) and if applicable the contract address (for token and NFT) and tokenID (for Non-Fungible Tokens). Once confirmed, the private-public keypair is generated and corresponding address is shown in the main menu.

For a given keyslot, the transition between status follows always the same cycle: 'Uninitialized' => 'Sealed' => 'Unsealed' => 'Uninitialized' => ...
Different keyslots on the same Satodime are completely unrelated and can have different status at any given time.

When a keyslot is unsealed, the private key is made available to the user and can be recovered by clicking on the 'more details' button of the corresponding slot. Once the private key is unsealed, it is no longer protected by the secure chip and any asset associated with the corresponding address should be transferred immediately to a new address. This is generally done by 'sweeping' the private key and many wallet provides this option (e.g. Electrum and Metamask). YOU SHOULD NEVER ACCEPT A SATODIME FROM SOMEONE IF A KEYSLOT IS UNSEALED!

Once a keyslot is unsealed and any asset has been transferred, you can reset the slot to return it in its 'Uninitialized' state and start a new cycle again.

## Development version (Windows)

Install the latest python 3.6 release from https://www.python.org (https://www.python.org/downloads/release/python-368/)
(Caution: installing another release than 3.6 may cause incompatibility issues with pyscard)

Clone or download the code from GitHub.
    
Install pyscard from https://pyscard.sourceforge.io/
Pyscard is required to connect to the smartcard::

    python -m pip install pyscard
    
In case of error message, you may also install pyscard from the installer:
Download the .whl files from https://sourceforge.net/projects/pyscard/files/pyscard/pyscard%201.9.7/ and run::

    python -m pip install pyscard-1.9.7-cp36-cp36m-win_amd64.whl

## Development version (Ubuntu)

Check out the code from GitHub::
    
    git clone git://github.com/Toporin/pysatochip.git
    cd pysatochip
    
Install pyscard (https://pyscard.sourceforge.io/)
Pyscard is required to connect to the smartcard:: 
    sudo apt-get install pcscd
    sudo apt-get install python3-pyscard
(For alternatives, see https://github.com/LudovicRousseau/pyscard/blob/master/INSTALL.md for more detailed installation instructions)

    

