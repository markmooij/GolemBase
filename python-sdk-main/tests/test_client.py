import os
import unittest
import logging
import xdg
from golem_base_sdk import create_client

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("GolemBaseTest")

# Read private key
key_path = os.path.join(xdg.xdg_config_home(), 'golembase', 'private.key')
with open(key_path, 'rb') as f:
    key_bytes = f.read()

class TestGolemBaseClient(unittest.TestCase):
    def setUp(self):
        self.client = create_client(key_bytes, 'http://localhost:8545', logger)
    
    def test_create_and_delete_entity(self):
        # Create an entity
        creates = [{
            "data": "test_data",
            "ttl": 25,
            "stringAnnotations": [["key", "test"]],
            "numericAnnotations": [["ix", 1]]
        }]
        
        receipts = self.client.create_entities(creates)
        self.assertEqual(len(receipts), 1)
        
        entity_key = receipts[0]["entityKey"]
        
        # Verify entity exists
        metadata = self.client.get_entity_metadata(entity_key)
        self.assertEqual(metadata["stringAnnotations"][0]["value"], "test")
        
        # Delete the entity
        delete_receipts = self.client.delete_entities([entity_key])
        self.assertEqual(len(delete_receipts), 1)
        
        # Verify entity is deleted
        with self.assertRaises(Exception):
            self.client.get_entity_metadata(entity_key)

if __name__ == '__main__':
    unittest.main()