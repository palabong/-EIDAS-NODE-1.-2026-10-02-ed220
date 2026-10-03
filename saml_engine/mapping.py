from datetime import datetime, timezone, date
from typing import Dict, Any, Optional, List

class POSUserContext:
    def __init__(
        self,
        user_id: str,
        role: str,
        permissions: List[str],
        level_of_assurance: str,
        store_id: str = "STORE-001",
        family_name: Optional[str] = None,
        given_name: Optional[str] = None,
        date_of_birth: Optional[str] = None,
        age: Optional[int] = None,
        is_over_18: Optional[bool] = None,
        is_over_21: Optional[bool] = None,
        raw_attributes: Optional[Dict[str, Any]] = None,
    ):
        self.user_id = user_id
        self.role = role
        self.permissions = permissions
        self.level_of_assurance = level_of_assurance
        self.store_id = store_id
        self.family_name = family_name
        self.given_name = given_name
        self.date_of_birth = date_of_birth
        self.age = age
        self.is_over_18 = is_over_18
        self.is_over_21 = is_over_21
        self.raw_attributes = raw_attributes or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "role": self.role,
            "permissions": self.permissions,
            "level_of_assurance": self.level_of_assurance,
            "store_id": self.store_id,
            "family_name": self.family_name,
            "given_name": self.given_name,
            "date_of_birth": self.date_of_birth,
            "age": self.age,
            "is_over_18": self.is_over_18,
            "is_over_21": self.is_over_21,
            "raw_attributes": self.raw_attributes,
        }

class SAMLToPOSMapper:
    MANDATORY_EIDAS_ATTRIBUTES = [
        "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier",
        "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName",
        "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName",
        "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth",
    ]

    FRIENDLY_TO_URI = {
        "PersonIdentifier": "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier",
        "CurrentFamilyName": "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName",
        "FamilyName": "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName",
        "CurrentGivenName": "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName",
        "GivenName": "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName",
        "FirstName": "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName",
        "DateOfBirth": "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth",
    }

    @staticmethod
    def calculate_age(dob_str: Optional[str], reference_date: Optional[date] = None) -> tuple[Optional[int], Optional[bool], Optional[bool]]:
        """
        Parses ISO format DateOfBirth (YYYY-MM-DD) and calculates current age, is_over_18, and is_over_21.
        """
        if not dob_str:
            return None, None, None
        
        try:
            # Handle standard YYYY-MM-DD
            clean_dob = dob_str.strip().split("T")[0]
            dob = datetime.strptime(clean_dob, "%Y-%m-%d").date()
            today = reference_date or datetime.now(timezone.utc).date()
            
            age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
            is_over_18 = age >= 18
            is_over_21 = age >= 21
            return age, is_over_18, is_over_21
        except Exception:
            return None, None, None

    @classmethod
    def extract_attribute(cls, attributes: Dict[str, Any], *keys: str) -> Optional[str]:
        """
        Finds attribute value by trying multiple keys (URI, friendly name, lowercase).
        """
        for key in keys:
            if key in attributes:
                val = attributes[key]
                if isinstance(val, list) and len(val) > 0:
                    return str(val[0])
                if val is not None:
                    return str(val)
            # Try lowercased/stripped
            for attr_k, attr_v in attributes.items():
                if attr_k.lower() == key.lower() or attr_k.endswith(f"/{key}"):
                    if isinstance(attr_v, list) and len(attr_v) > 0:
                        return str(attr_v[0])
                    if attr_v is not None:
                        return str(attr_v)
        return None

    @classmethod
    def map_claims_to_pos(cls, claims: Dict[str, Any]) -> POSUserContext:
        """
        Maps standard SAML claims extracted from the eIDAS schemas into actionable POS roles & permissions.
        Properly extracts eIDAS natural person profile attributes:
        - PersonIdentifier -> user_id
        - CurrentFamilyName -> family_name
        - CurrentGivenName -> given_name
        - DateOfBirth -> date_of_birth, age, is_over_18, is_over_21
        """
        attributes = claims.get("attributes") or {}
        # Also check top-level claims for direct attributes
        combined = {**claims, **attributes}

        # 1. Extract PersonIdentifier as user_id (Mandatory eIDAS Natural Person Attribute)
        person_identifier = cls.extract_attribute(
            combined,
            "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier",
            "PersonIdentifier",
            "person_identifier"
        )

        # Fallback only if PersonIdentifier is completely missing (e.g. mock AuthnRequest or Subject NameID)
        if not person_identifier:
            name_id = claims.get("name_id") or claims.get("subject")
            if name_id:
                person_identifier = name_id
            else:
                subj_raw = claims.get("id", "UNKNOWN_SUBJECT")
                person_identifier = f"ID-{subj_raw[-8:]}" if len(subj_raw) > 8 else subj_raw

        user_id = person_identifier

        # 2. Extract Natural Person Attributes
        family_name = cls.extract_attribute(
            combined,
            "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName",
            "CurrentFamilyName",
            "FamilyName",
            "family_name"
        )

        given_name = cls.extract_attribute(
            combined,
            "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName",
            "CurrentGivenName",
            "GivenName",
            "FirstName",
            "given_name"
        )

        date_of_birth = cls.extract_attribute(
            combined,
            "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth",
            "DateOfBirth",
            "date_of_birth"
        )

        age, is_over_18, is_over_21 = cls.calculate_age(date_of_birth)

        # 3. Level of Assurance (LoA) Mapping
        loa_uri = str(claims.get("level_of_assurance") or "")
        loa_upper = loa_uri.upper()

        if "HIGH" in loa_upper:
            loa_level = "HIGH"
        elif "SUBSTANTIAL" in loa_upper:
            loa_level = "SUBSTANTIAL"
        else:
            loa_level = "LOW"

        # Retail demographic & role gating:
        # Minors (<18) must NEVER be granted STORE_MANAGER or elevated supervisor permissions regardless of LoA.
        if is_over_18 is False:
            role = "CASHIER"
            permissions = [
                "SHIFT_START",
                "SCAN_ITEM",
                "APPLY_COUPON",
                "CASH_TRANSACTION",
            ]
        elif loa_level == "HIGH":
            role = "STORE_MANAGER"
            permissions = [
                "SHIFT_START",
                "SCAN_ITEM",
                "APPLY_COUPON",
                "CASH_TRANSACTION",
                "MANAGER_OVERRIDE",
                "VOID_TRANSACTION",
                "REFUND_OVERRIDE",
                "DRAWER_ACCESS",
                "ELEVATED_AUDIT_LOG_EXPORT",
            ]
        elif loa_level == "SUBSTANTIAL":
            role = "STORE_MANAGER"
            permissions = [
                "SHIFT_START",
                "SCAN_ITEM",
                "APPLY_COUPON",
                "CASH_TRANSACTION",
                "MANAGER_OVERRIDE",
                "VOID_TRANSACTION",
                "REFUND_OVERRIDE",
                "DRAWER_ACCESS",
            ]
        else:
            role = "CASHIER"
            permissions = [
                "SHIFT_START",
                "SCAN_ITEM",
                "APPLY_COUPON",
                "CASH_TRANSACTION",
            ]

        issuer = str(claims.get("issuer") or "")
        store_id = "STORE-BELGIUM-BRU-01" if ("Belgium" in issuer or "S-PEPS.gov.xx" in issuer) else "STORE-METADATA-01"

        return POSUserContext(
            user_id=user_id,
            role=role,
            permissions=permissions,
            level_of_assurance=loa_level,
            store_id=store_id,
            family_name=family_name,
            given_name=given_name,
            date_of_birth=date_of_birth,
            age=age,
            is_over_18=is_over_18,
            is_over_21=is_over_21,
            raw_attributes=attributes,
        )
