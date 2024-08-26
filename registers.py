import os
import json
from typing import Annotated
from autogen import register_function
import requests
from dotenv import load_dotenv



def register_functions(assistant, user_proxy):
    '''
    Register function for Autogen
    '''

    register_function(
        vt_get_hash,
        caller = assistant,
        executor = user_proxy,
        description = "given a hash, return the likleyhood the information \
            and likleyhood of it being malicious"
    )

    register_function(
        circl_get_hash,
        caller = assistant,
        executor = user_proxy,
        description = "given a hash, return the data available from circl.lu"
    )

    register_function(
        type_of_hash,
        caller = assistant,
        executor = user_proxy,
        description = "given a hash, return the hash type (sha1, sha256, or md5)"
    )


def vt_get_hash(hashn: Annotated[str, "Hash Value for checking the hash information"]) -> json:
    '''
    Function call to get hash information from Virustotal to use in autogen AI
    '''

    load_dotenv()
    hash_id = hashn
    headers = {"accept": "application/json",
               "x-apikey": os.environ.get("VT_API_KEY")
    }
    r = requests.get(f"https://www.virustotal.com/api/v3/files/{hash_id}",
                     headers=headers, timeout=600)
    return r.json()

def type_of_hash(hashn: Annotated[str, "Get the hash type (sha1, sha256, md5) from hash value"]) -> str:
    '''
    get hash type based on length of hash
    '''

    if len(hashn) == 64:
        return "sha256"
    elif len(hashn) == 40:
        return "sha1"
    elif len(hashn) == 32:
        return "md5"
    return "not a valid hash, TERMINATE"

def circl_get_hash(hashn: Annotated[str, "Hash Value for checking the hash information from circl.lu"], hash_type: Annotated[str, "Type (valid: sha256, sha1, md5) of the hash from the hash value"]) -> json:
    '''
    Function call to get hash information from Virustotal to use in autogen AI
    '''

    load_dotenv()
    hash_id = hashn
    headers = {"accept": "application/json"}
    r = requests.get(f"https://hashlookup.circl.lu/lookup/{hash_type}/{hash_id}", 
                     headers=headers, timeout=600)
    return r.json()
