# This code is part of Qiskit.
#
# (C) Copyright IBM 2021.
#
# This code is licensed under the Apache License, Version 2.0. You may
# obtain a copy of this license in the LICENSE.txt file in the root directory
# of this source tree or at http://www.apache.org/licenses/LICENSE-2.0.
#
# Any modifications or derivative works of this code must retain this
# copyright notice, and modified files need to carry a notice indicating
# that they have been altered from the originals.

"""Authentication helpers."""

from typing import Dict


from requests import PreparedRequest
from requests.auth import AuthBase
from ibm_cloud_sdk_core.token_managers.iam_token_manager import IAMTokenManager
from ..utils.utils import get_iam_api_url


class CloudAuth(AuthBase):
    """Attaches IBM Cloud Authentication to the given Request object."""

    def __init__(self, api_key: str, crn: str, url: str):
        self.token_manager = IAMTokenManager(api_key, url=get_iam_api_url(url))
        self.crn = crn

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CloudAuth):
            return all(
                [
                    self.api_key == other.api_key,
                    self.crn == other.crn,
                ]
            )
        return False

    def __call__(self, r: PreparedRequest) -> PreparedRequest:
        r.headers.update(self.get_headers())
        return r

    def get_headers(self) -> Dict:
        """Return authorization information to be stored in header."""
        bearer = self.token_manager.get_token()
        return {"Service-CRN": self.crn, "Authorization": f"Bearer {bearer}"}


class QuantumAuth(AuthBase):
    """Attaches IBM Quantum Authentication to the given Request object."""

    def __init__(self, access_token: str):
        self.access_token = access_token

    def __eq__(self, other: object) -> bool:
        if isinstance(other, QuantumAuth):
            return self.access_token == other.access_token

        return False

    def __call__(self, r: PreparedRequest) -> PreparedRequest:
        r.headers.update(self.get_headers())
        return r

    def get_headers(self) -> Dict:
        """Return authorization information to be stored in header."""
        return {"X-Access-Token": self.access_token}
