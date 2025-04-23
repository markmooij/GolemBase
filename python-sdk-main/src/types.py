from typing import List, Dict, Tuple, Optional, Union, TypedDict, NewType

# Type for hexadecimal strings
Hex = NewType('Hex', str)

class GolemBaseCreate(TypedDict):
    """Type representing a create transaction in GolemBase"""
    data: str
    ttl: int
    stringAnnotations: List[Tuple[str, str]]
    numericAnnotations: List[Tuple[str, int]]

class GolemBaseUpdate(TypedDict):
    """Type representing an update transaction in GolemBase"""
    entityKey: Hex
    data: str
    ttl: int
    stringAnnotations: List[Tuple[str, str]]
    numericAnnotations: List[Tuple[str, int]]

class GolemBaseExtend(TypedDict):
    """Type representing an extend transaction in GolemBase"""
    entityKey: Hex
    numberOfBlocks: int

class GolemBaseTransaction(TypedDict, total=False):
    """Type representing a transaction in GolemBase"""
    creates: Optional[List[GolemBaseCreate]]
    updates: Optional[List[GolemBaseUpdate]]
    deletes: Optional[List[Hex]]
    extensions: Optional[List[GolemBaseExtend]]

class StringAnnotation(TypedDict):
    key: str
    value: str

class NumericAnnotation(TypedDict):
    key: str
    value: int

class EntityMetaData(TypedDict):
    """Type representing entity metadata in GolemBase"""
    expiresAtBlock: int
    stringAnnotations: List[StringAnnotation]
    numericAnnotations: List[NumericAnnotation]
    owner: Hex