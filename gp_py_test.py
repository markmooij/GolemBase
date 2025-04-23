import os
import logging
import time
import base64
import json
from src import create_client

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("GolemBaseTest")

# Read private key
with open('PATHTOPRIVATEKEY', 'rb') as f:
    key_bytes = f.read()

# Create client
client = create_client(key_bytes, 'http://localhost:8545', logger)

def test_create_entity():
    """Test creating an entity"""
    logger.info("Testing create_entities...")
    
    creates = [{
        "data": "Hello, GolemBase!",
        "ttl": 25,
        "stringAnnotations": [["key", "greeting"], ["test", "create"]],
        "numericAnnotations": [["ix", 1], ["test", 100]]
    }]
    
    # creates = [{
    #     "data": json.dumps([{"status" : "ok"}]),
    #     "ttl": 25,
    #     "stringAnnotations": [["status", "ok"]],
    #     "numericAnnotations": [["ix", 1], ["date", 1745331981]]
    # }]
    
    
    receipts = client.create_entities(creates)
    logger.info(f"Created entity with receipt: {receipts}")
    
    entity_key = receipts[0]["entityKey"]
    
    # Convert bytes to hex string if needed
    if isinstance(entity_key, bytes):
        entity_key = entity_key.hex()
        # Add 0x prefix if not present
        if not entity_key.startswith('0x'):
            entity_key = f'0x{entity_key}'
    
    logger.info(f"Entity key: {entity_key}")
    
    return entity_key

def test_get_entity_metadata(entity_key):
    """Test getting entity metadata"""
    logger.info("Testing get_entity_metadata...")
    
    metadata = client.get_entity_metadata(entity_key)
    logger.info(f"Entity metadata: {metadata}")
    
    return metadata

def test_get_storage_value(entity_key):
    """Test getting storage value"""
    logger.info("Testing get_storage_value...")
    
    # Get with automatic decoding
    value = client.get_storage_value(entity_key)
    logger.info(f"Storage value (decoded): {value}")
    
    # Get without decoding
    raw_value = client.get_storage_value(entity_key, decode_base64=False)
    logger.info(f"Storage value (raw): {raw_value}")
    
    return value

def test_update_entity(entity_key):
    """Test updating an entity"""
    logger.info("Testing update_entities...")
    
    updates = [{
        "entityKey": entity_key,
        "ttl": 40,
        "data": "Updated greeting!",
        "stringAnnotations": [["key", "greeting"], ["updated", "true"], ["test", "update"]],
        "numericAnnotations": [["ix", 2], ["test", 200]]
    }]
    
    receipts = client.update_entities(updates)
    logger.info(f"Updated entity with receipt: {receipts}")
    
    # Verify the update
    value = client.get_storage_value(entity_key)
    logger.info(f"Updated storage value: {value}")
    
    return receipts

def test_data_update_entity(entity_key, data, metadata):
    """Test updating an data entity"""
    logger.info("Testing data update_entities...")
    
    # Convert metadata annotations from dict format to list format
    string_annotations = []
    if "stringAnnotations" in metadata and metadata["stringAnnotations"]:
        string_annotations = [[item["key"], item["value"]] for item in metadata["stringAnnotations"]]
    
    numeric_annotations = []
    if "numericAnnotations" in metadata and metadata["numericAnnotations"]:
        numeric_annotations = [[item["key"], item["value"]] for item in metadata["numericAnnotations"]]
    
    updates = [{
        "entityKey": entity_key,
        "ttl": 40,
        "data": json.dumps(data),
        "stringAnnotations": string_annotations,
        "numericAnnotations": numeric_annotations
    }]
    
    receipts = client.update_entities(updates)
    logger.info(f"Updated entity with receipt: {receipts}")
    
    # Verify the update
    value = client.get_storage_value(entity_key)
    logger.info(f"Updated storage value: {value}")
    
    return receipts

def test_extend_entity(entity_key):
    """Test extending an entity's TTL"""
    logger.info("Testing extend_entities...")
    
    extensions = [{
        "entityKey": entity_key,
        "numberOfBlocks": 50
    }]
    
    receipts = client.extend_entities(extensions)
    logger.info(f"Extended entity with receipt: {receipts}")
    
    # Verify the extension
    metadata = client.get_entity_metadata(entity_key)
    logger.info(f"Entity metadata after extension: {metadata}")
    
    return receipts

def test_query_functions():
    """Test various query functions"""
    logger.info("Testing query functions...")
    
    # Get owner address
    owner_address = client.get_owner_address()
    logger.info(f"Owner address: {owner_address}")
    
    # Get entity count
    entity_count = client.get_entity_count()
    logger.info(f"Entity count: {entity_count}")
    
    # Get all entity keys
    all_keys = client.get_all_entity_keys()
    logger.info(f"All entity keys: {all_keys}")
    
    # Get entities of owner
    owner_entities = client.get_entities_of_owner(owner_address)
    logger.info(f"Owner entities: {owner_entities}")
    
    # Get entities with string annotation
    string_annotated = client.get_entities_for_string_annotation_value("test", "create")
    logger.info(f"Entities with string annotation 'test=create': {string_annotated}")
    
    # Get entities with numeric annotation
    numeric_annotated = client.get_entities_for_numeric_annotation_value("test", 100)
    logger.info(f"Entities with numeric annotation 'test=100': {numeric_annotated}")
    
    # Get entities to expire at a specific block
    # First, get the current block number
    current_block = client.web3.eth.block_number
    future_block = current_block + 25  # Assuming TTL was 25
    expire_at_block = client.get_entities_to_expire_at_block(future_block)
    logger.info(f"Entities to expire at block {future_block}: {expire_at_block}")
    
    return {
        "owner_address": owner_address,
        "entity_count": entity_count,
        "all_keys": all_keys,
        "owner_entities": owner_entities,
        "string_annotated": string_annotated,
        "numeric_annotated": numeric_annotated,
        "expire_at_block": expire_at_block
    }

def test_delete_entity(entity_key):
    """Test deleting an entity"""
    logger.info("Testing delete_entities...")
    
    receipts = client.delete_entities([entity_key])
    logger.info(f"Deleted entity with receipt: {receipts}")
    
    # Verify the deletion
    try:
        metadata = client.get_entity_metadata(entity_key)
        logger.info(f"Entity metadata after deletion (should be empty): {metadata}")
    except Exception as e:
        logger.info(f"Entity was successfully deleted: {e}")
    
    return receipts

def run_all_tests():
    """Run all tests in sequence"""
    try:
        # Create an entity and get its key
        entity_key = test_create_entity()
        
        # # Test getting metadata and storage value
        # entity_key = "0x437b7320e630afbc9caf9da3984e70e21d145d0e7e379700080cef521a235d79"
        metadata = test_get_entity_metadata(entity_key)
        value = test_get_storage_value(entity_key)
        # print(metadata)

        # value = json.loads(value)
        # value.append({"status": "ok"})

        # Test updating the data entity        
        # test_data_update_entity(entity_key, value, metadata)

        # Test updating the entity
        test_update_entity(entity_key)        
        
        # Test extending the entity's TTL
        test_extend_entity(entity_key)
        
        # Test query functions
        test_query_functions()
        
        # Test deleting the entity
        test_delete_entity(entity_key)
        
        logger.info("All tests completed successfully!")
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        raise

if __name__ == "__main__":
    run_all_tests()