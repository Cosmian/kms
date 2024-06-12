# -*- coding: utf-8 -*-
from typing import List, Union

from .cosmian_kms import *

UidOrTags = Union[str, List[str]]
# KMS Objects (e.g. keys) can either be referenced by an UID using a single string,
# or by a list of tags using a list of string.

__doc__ = cosmian_kms.__doc__
if hasattr(cosmian_kms, '__all__'):
    __all__ = cosmian_kms.__all__
