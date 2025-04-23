import os
import logging
import xdg
from golem_base_sdk import create_client, GolemBaseCreate

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("GolemBaseExample")

# Read private key
key_path = os.path.join(xdg.xdg_config_home(), 'golembase', 'private.key')
with open(key_path, 'rb') as f:
    key_bytes = f.read()

def main():
    # Create client
    client = create_client(key_bytes, 'http://localhost:8545', logger)
    
    async def num_of_entities_owned():
        return len(await client.get_entities_of_owner(await client.get_owner_address()))
    
    logger.info(f"Number of entities owned: {num_of_entities_owned()}")
    
    logger.info("")
    logger.info("*********************")
    logger.info("* Creating entities *")
    logger.info("*********************")
    logger.info("")
    
    creates = [
        {
            "data": "foo",
            "ttl": 25,
            "stringAnnotations": [["key", "foo"]],
            "numericAnnotations": [["ix", 1]]
        },
        {
            "data": "bar",
            "ttl": 2,
            "stringAnnotations": [["key", "bar"]],
            "numericAnnotations": [["ix", 2]]
        },
        {
            "data": "qux",
            "ttl": 50,
            "stringAnnotations": [["key", "qux"]],
            "numericAnnotations": [["ix", 2]]
        }
    ]
    
    receipts = client.create_entities(creates)
    
    logger.info(f"Number of entities owned: {num_of_entities_owned()}")
    
    logger.info("")
    logger.info("*************************")
    logger.info("* Deleting first entity *")
    logger.info("*************************")
    logger.info("")
    
    client.delete_entities([receipts[0]["entityKey"]])
    logger.info(f"Number of entities owned: {num_of_entities_owned()}")
    
    logger.info("")
    logger.info("*****************************")
    logger.info("* Updating the third entity *")
    logger.info("*****************************")
    logger.info("")
    
    entity_key = receipts[2]["entityKey"]
    metadata = client.get_entity_metadata(entity_key)
    storage_value = client.get_storage_value(entity_key)
    
    logger.info(f"The third entity before the update: {metadata}")
    logger.info(f"Storage value: {storage_value}")
    
    logger.info("Updating the entity...")
    client.update_entities([{
        "entityKey": entity_key,
        "ttl": 40,
        "data": "foobar",
        "stringAnnotations": [["key", "qux"], ["foo", "bar"]],
        "numericAnnotations": [["ix", 2]]
    }])
    
    metadata = client.get_entity_metadata(entity_key)
    storage_value = client.get_storage_value(entity_key)
    
    logger.info(f"The third entity after the update: {metadata}")
    logger.info(f"Storage value: {storage_value}")
    
    logger.info(f"Number of entities owned: {num_of_entities_owned()}")
    
    logger.info("")
    logger.info("*******************************")
    logger.info("* Deleting remaining entities *")
    logger.info("*******************************")
    logger.info("")
    
    query_results = client.query_entities("ix = 1 || ix = 2 || ix = 3")
    client.delete_entities([result["key"] for result in query_results])
    
    logger.info(f"Number of entities owned: {num_of_entities_owned()}")

if __name__ == "__main__":
    main()