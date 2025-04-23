import json
import logging
import binascii
import requests
from typing import List, Dict, Tuple, Optional, Union, Any, TypedDict, cast
from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_utils import to_hex, to_checksum_address, keccak
from web3 import Web3

from .types import (
    GolemBaseCreate,
    GolemBaseUpdate,
    GolemBaseExtend,
    GolemBaseTransaction,
    EntityMetaData,
    Hex
)
from . import rlp

# Storage contract address
STORAGE_ADDRESS = '0x0000000000000000000000000000000060138453'

class GolemBaseClient:
    """Client to interact with GolemBase"""
    
    def __init__(self, account: LocalAccount, rpc_url: str, logger=None):
        """
        Initialize a GolemBase client
        
        Args:
            account: Ethereum account for signing transactions
            rpc_url: JSON-RPC URL to talk to
            logger: Optional logger instance
        """
        self.account = account
        self.rpc_url = rpc_url
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        self.logger = logger or logging.getLogger("GolemBaseClient")
        self.nonce = None
    
    def _get_nonce(self) -> int:
        """Get the next nonce for the account"""
        if self.nonce is None:
            self.nonce = self.web3.eth.get_transaction_count(self.account.address)
        else:
            self.nonce += 1
        return self.nonce
    
    def _create_payload(self, tx: GolemBaseTransaction) -> str:
        """Create RLP encoded payload for a transaction"""
        if self.logger:
            self.logger.debug(f"Transaction: {json.dumps(tx, default=str)}")
        
        payload = [
            # Create
            [(el['ttl'], el['data'], el['stringAnnotations'], el['numericAnnotations']) 
             for el in tx.get('creates', [])],
            # Update
            [(el['entityKey'], el['ttl'], el['data'], el['stringAnnotations'], el['numericAnnotations']) 
             for el in tx.get('updates', [])],
            # Delete
            tx.get('deletes', []),
            # Extend
            [(el['entityKey'], el['numberOfBlocks']) 
             for el in tx.get('extensions', [])]
        ]
        
        if self.logger:
            self.logger.debug(f"Payload before RLP encoding: {json.dumps(payload, default=str)}")
        
        encoded = rlp.encode(payload)
        return to_hex(encoded)
    
    def _send_rpc_request(self, method: str, params: List[Any]) -> Any:
        """Send a JSON-RPC request to the node"""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }
        
        response = requests.post(self.rpc_url, json=payload)
        response_data = response.json()
        
        if "error" in response_data:
            raise ValueError(f"RPC Error: {response_data['error']}")
        
        return response_data["result"]
    
    def _create_raw_storage_transaction(self, payload: str) -> str:
        """Create and sign a raw transaction to the storage contract"""
        tx_params = {
            'to': STORAGE_ADDRESS,
            'value': 0,
            'gas': 1000000,
            'maxFeePerGas': 150000000000,
            'maxPriorityFeePerGas': 1000000000,
            'nonce': self._get_nonce(),
            'data': payload,
            'chainId': 1337,  # Golem Base chain ID
            'type': 2  # EIP-1559 transaction
        }
        
        signed_tx = self.account.sign_transaction(tx_params)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        
        if self.logger:
            self.logger.debug(f"Got transaction hash: {tx_hash.hex()}")
        
        return tx_hash.hex()
    
    def _wait_for_transaction_receipt(self, tx_hash: str) -> Dict[str, Any]:
        """Wait for a transaction receipt"""
        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        return dict(receipt)
    
    def get_owner_address(self) -> str:
        """Get the address of the account"""
        return self.account.address
    
    def get_storage_value(self, key: str) -> str:
        """Get the storage value associated with the given entity key"""
        result = self._send_rpc_request("golembase_getStorageValue", [key])
        return result
    
    def get_entity_metadata(self, key: str) -> EntityMetaData:
        """Get the full entity information"""
        result = self._send_rpc_request("golembase_getEntityMetaData", [key])
        return cast(EntityMetaData, result)
    
    def get_entities_to_expire_at_block(self, block_number: int) -> List[str]:
        """Get all entity keys for entities that will expire at the given block number"""
        result = self._send_rpc_request("golembase_getEntitiesToExpireAtBlock", [block_number])
        return result or []
    
    def get_entities_for_string_annotation_value(self, key: str, value: str) -> List[str]:
        """Get entities with a specific string annotation value"""
        result = self._send_rpc_request("golembase_getEntitiesForStringAnnotationValue", [key, value])
        return result or []
    
    def get_entities_for_numeric_annotation_value(self, key: str, value: int) -> List[str]:
        """Get entities with a specific numeric annotation value"""
        result = self._send_rpc_request("golembase_getEntitiesForNumericAnnotationValue", [key, value])
        return result or []
    
    def get_entity_count(self) -> int:
        """Get the total number of entities"""
        return self._send_rpc_request("golembase_getEntityCount", [])
    
    def get_all_entity_keys(self) -> List[str]:
        """Get all entity keys"""
        result = self._send_rpc_request("golembase_getAllEntityKeys", [])
        return result or []
    
    def get_entities_of_owner(self, address: str) -> List[str]:
        """Get all entities owned by an address"""
        result = self._send_rpc_request("golembase_getEntitiesOfOwner", [address])
        return result or []
    
    def query_entities(self, query: str) -> List[Dict[str, str]]:
        """Query entities based on a query string"""
        result = self._send_rpc_request("golembase_queryEntities", [query])
        return result or []
    
    def create_entities(self, creates: List[GolemBaseCreate]) -> List[Dict[str, Any]]:
        """Create entities"""
        tx_hash = self._create_raw_storage_transaction(
            self._create_payload({"creates": creates})
        )
        receipt = self._wait_for_transaction_receipt(tx_hash)
        
        if self.logger:
            self.logger.debug(f"Got receipt: {receipt}")
        
        return [
            {
                "expirationBlock": int(log["data"], 16),
                "entityKey": log["topics"][1]
            }
            for log in receipt["logs"]
        ]
    
    def update_entities(self, updates: List[GolemBaseUpdate]) -> List[Dict[str, Any]]:
        """Update entities"""
        tx_hash = self._create_raw_storage_transaction(
            self._create_payload({"updates": updates})
        )
        receipt = self._wait_for_transaction_receipt(tx_hash)
        
        if self.logger:
            self.logger.debug(f"Got receipt: {receipt}")
        
        return [
            {
                "expirationBlock": int(log["data"], 16),
                "entityKey": log["topics"][1]
            }
            for log in receipt["logs"]
        ]
    
    def delete_entities(self, deletes: List[str]) -> List[Dict[str, Any]]:
        """Delete entities"""
        tx_hash = self._create_raw_storage_transaction(
            self._create_payload({"deletes": deletes})
        )
        receipt = self._wait_for_transaction_receipt(tx_hash)
        
        if self.logger:
            self.logger.debug(f"Got receipt: {receipt}")
        
        return [
            {
                "entityKey": log["topics"][1]
            }
            for log in receipt["logs"]
        ]
    
    def extend_entities(self, extensions: List[GolemBaseExtend]) -> List[Dict[str, Any]]:
        """Extend entities"""
        tx_hash = self._create_raw_storage_transaction(
            self._create_payload({"extensions": extensions})
        )
        receipt = self._wait_for_transaction_receipt(tx_hash)
        
        if self.logger:
            self.logger.debug(f"Got receipt: {receipt}")
        
        return [
            {
                "oldExpirationBlock": int(log["data"][2:66], 16),
                "newExpirationBlock": int(log["data"][66:130], 16),
                "entityKey": log["topics"][1]
            }
            for log in receipt["logs"]
        ]

def create_client(key: bytes, rpc_url: str, logger=None) -> GolemBaseClient:
    """
    Create a client to interact with GolemBase
    
    Args:
        key: Private key for this client
        rpc_url: JSON-RPC URL to talk to
        logger: Optional logger instance
    
    Returns:
        A client object
    """
    account = Account.from_key(key)
    return GolemBaseClient(account, rpc_url, logger)