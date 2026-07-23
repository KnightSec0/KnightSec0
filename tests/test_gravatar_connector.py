import asyncio
import hashlib
import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx


ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))

from config import settings
from connectors.gravatar import GravatarProfileConnector
from intelligence.models import IdentityStatus, InvestigationTarget
from intelligence.policy import CollectionPolicy
from investigators.person_intelligence import PersonIntelligenceInvestigator


def response(status_code, payload=None):
    request = httpx.Request("GET", "https://api.gravatar.com/v3/profiles/test")
    return httpx.Response(status_code, json=payload, request=request)


class GravatarProfileConnectorTests(unittest.TestCase):
    def test_public_profile_is_allowlisted_and_email_hash_is_not_persisted(self):
        email = "Alice.Example@Example.test"
        normalized_email = email.casefold()
        email_hash = hashlib.sha256(normalized_email.encode("utf-8")).hexdigest()
        connector = GravatarProfileConnector()
        connector._get = AsyncMock(
            return_value=response(
                200,
                {
                    "hash": email_hash,
                    "email": normalized_email,
                    "display_name": "Alice Example",
                    "preferred_username": "alice",
                    "description": "Security researcher",
                    "location": "Paris",
                    "profile_url": "https://gravatar.com/alice",
                    "avatar_url": f"https://gravatar.com/avatar/{email_hash}",
                    "company": normalized_email,
                    "unknown_private_field": "must-not-survive",
                    "verified_accounts": [
                        {
                            "service_label": "GitHub",
                            "service_type": "github",
                            "url": "https://github.com/alice",
                            "is_hidden": False,
                            "username": "must-not-survive",
                        },
                        {
                            "service_label": "Hidden",
                            "service_type": "example",
                            "url": "https://example.test/private",
                            "is_hidden": True,
                        },
                        {
                            "service_label": "Unsafe",
                            "service_type": "email",
                            "url": "mailto:alice@example.test",
                            "is_hidden": False,
                        },
                    ],
                },
            )
        )

        with patch.object(settings, "gravatar_api_key", None):
            result = asyncio.run(connector.search(email))

        connector._get.assert_awaited_once()
        request_url = connector._get.await_args.args[0]
        request_headers = connector._get.await_args.kwargs["headers"]
        self.assertEqual(
            request_url,
            f"https://api.gravatar.com/v3/profiles/{email_hash}",
        )
        self.assertNotIn("Authorization", request_headers)
        self.assertEqual(len(result.evidence), 1)

        evidence = result.evidence[0]
        self.assertEqual(evidence.source, "gravatar")
        self.assertEqual(evidence.value, "https://gravatar.com/alice")
        self.assertEqual(evidence.identity_status, IdentityStatus.POSSIBLE)
        public_profile = evidence.metadata
        self.assertEqual(
            public_profile["verified_accounts"],
            [
                {
                    "url": "https://github.com/alice",
                    "label": "GitHub",
                    "type": "github",
                }
            ],
        )
        self.assertNotIn("hash", public_profile)
        self.assertNotIn("email", public_profile)
        self.assertNotIn("unknown_private_field", public_profile)
        self.assertNotIn("company", public_profile)
        self.assertNotIn("avatar_url", public_profile)
        serialized = json.dumps(evidence.model_dump(mode="json"))
        self.assertNotIn(normalized_email, serialized)
        self.assertNotIn(email_hash, serialized)
        self.assertIn("self-published", " ".join(evidence.notes))

    def test_optional_bearer_auth_is_sent_but_not_stored(self):
        connector = GravatarProfileConnector()
        connector._get = AsyncMock(
            return_value=response(
                200,
                {
                    "display_name": "Alice Example",
                    "profile_url": "https://gravatar.com/alice",
                },
            )
        )

        with patch.object(settings, "gravatar_api_key", "test-api-secret"):
            result = asyncio.run(connector.search("alice@example.test"))

        request_headers = connector._get.await_args.kwargs["headers"]
        self.assertEqual(request_headers["Authorization"], "Bearer test-api-secret")
        self.assertNotIn(
            "test-api-secret",
            json.dumps(result.model_dump(mode="json")),
        )

    def test_not_found_and_invalid_email_return_no_evidence(self):
        connector = GravatarProfileConnector()
        connector._get = AsyncMock(return_value=response(404, {}))

        not_found = asyncio.run(connector.search("alice@example.test"))
        invalid = asyncio.run(connector.search("not-an-email"))

        self.assertEqual(not_found.evidence, [])
        self.assertEqual(not_found.errors, [])
        self.assertEqual(invalid.evidence, [])
        self.assertEqual(invalid.errors, ["Invalid email address"])
        connector._get.assert_awaited_once()

    def test_authorized_email_is_routed_when_gravatar_is_permitted(self):
        target = InvestigationTarget(
            name="Alice Example",
            emails=["alice@example.test"],
            lawful_purpose="Authorized defensive review",
            authorization_confirmed=True,
        )
        policy = CollectionPolicy(
            authorization_reference="AUTH-123",
            purpose=target.lawful_purpose,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            permitted_sources=frozenset({"gravatar"}),
        )

        investigator = PersonIntelligenceInvestigator(policy)
        plan = investigator.build_plan(target=target)

        self.assertIn("gravatar", investigator.connectors)
        self.assertEqual(
            [
                (request.source, request.identifier, request.identifier_type)
                for request in plan
            ],
            [("gravatar", "alice@example.test", "email")],
        )


if __name__ == "__main__":
    unittest.main()
