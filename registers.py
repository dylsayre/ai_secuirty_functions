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
        get_hash,
        caller = assistant,
        executor = user_proxy,
        description = "given a hash, return the likleyhood the information and likleyhood of it being malicious"
    )


def get_hash(hashn: Annotated[str, "Hash Value for checking the hash information"]) -> json:
    '''
    Function call to get hash information from Virustotal to use in autogen AI
    '''

    load_dotenv()
    hash_id = hashn
    headers = {"accept": "application/json",
               "x-apikey": os.environ.get("VT_API_KEY")
    }
    r = requests.get(f"https://www.virustotal.com/api/v3/files/{hash_id}", headers=headers, timeout=600)
    return r.json()
