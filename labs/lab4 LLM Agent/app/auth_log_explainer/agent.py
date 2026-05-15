import os
from collections import Counter
from typing import Annotated, Dict, List

from agent_framework import ai_function
from agent_framework.openai import OpenAIChatClient
from pydantic import Field

AUTH_EVENTS: List[Dict[str, object]] = [
    {
        "event_id": "evt-1001",
        "user": "alice",
        "source_country": "IL",
        "protocol": "vpn",
        "result": "success",
        "failed_attempts_10m": 0,
        "off_hours": False,
        "new_device": False,
    },
    {
        "event_id": "evt-1002",
        "user": "bob",
        "source_country": "US",
        "protocol": "web_portal",
        "result": "success",
        "failed_attempts_10m": 0,
        "off_hours": False,
        "new_device": False,
    },
    {
        "event_id": "evt-1003",
        "user": "charlie",
        "source_country": "DE",
        "protocol": "ssh",
        "result": "failure",
        "failed_attempts_10m": 2,
        "off_hours": False,
        "new_device": False,
    },
    {
        "event_id": "evt-1004",
        "user": "bob",
        "source_country": "RU",
        "protocol": "ssh",
        "result": "failure",
        "failed_attempts_10m": 14,
        "off_hours": True,
        "new_device": True,
    },
    {
        "event_id": "evt-1005",
        "user": "bob",
        "source_country": "RU",
        "protocol": "ssh",
        "result": "failure",
        "failed_attempts_10m": 18,
        "off_hours": True,
        "new_device": True,
    },
    {
        "event_id": "evt-1006",
        "user": "admin",
        "source_country": "CN",
        "protocol": "vpn",
        "result": "success",
        "failed_attempts_10m": 6,
        "off_hours": True,
        "new_device": True,
    },
    {
        "event_id": "evt-1007",
        "user": "admin",
        "source_country": "IL",
        "protocol": "vpn",
        "result": "success",
        "failed_attempts_10m": 0,
        "off_hours": False,
        "new_device": False,
    },
    {
        "event_id": "evt-1008",
        "user": "alice",
        "source_country": "FR",
        "protocol": "vpn",
        "result": "success",
        "failed_attempts_10m": 1,
        "off_hours": True,
        "new_device": True,
    },
]

EXPECTED_COUNTRIES: Dict[str, List[str]] = {
    "alice": ["IL"],
    "bob": ["US"],
    "charlie": ["DE"],
    "admin": ["IL", "US"],
}


def _find_event(event_id: str) -> Dict[str, object] | None:
    for event in AUTH_EVENTS:
        if event["event_id"] == event_id:
            return event
    return None


def _is_unusual_country(event: Dict[str, object]) -> bool:
    user = str(event["user"])
    country = str(event["source_country"])
    return country not in EXPECTED_COUNTRIES.get(user, [])


def _build_reasons(event: Dict[str, object]) -> List[str]:
    reasons: List[str] = []

    if int(event["failed_attempts_10m"]) >= 10:
        reasons.append("high number of failed attempts in a short time window")
    elif int(event["failed_attempts_10m"]) >= 5:
        reasons.append("multiple failed attempts before the current event")

    if bool(event["off_hours"]):
        reasons.append("activity happened outside normal working hours")

    if bool(event["new_device"]):
        reasons.append("activity came from a new or unseen device")

    if _is_unusual_country(event):
        reasons.append("source country is unusual for this user")

    return reasons


def _classify_event(event: Dict[str, object]) -> Dict[str, object]:
    reasons = _build_reasons(event)
    result = str(event["result"])

    if result == "failure" and int(event["failed_attempts_10m"]) >= 10:
        return {
            "severity": "high",
            "classification": "likely_brute_force",
            "attack_hypothesis": "The pattern resembles repeated password guessing.",
            "mitre_techniques": ["T1110 - Brute Force"],
            "reasons": reasons,
        }

    if result == "success" and bool(event["off_hours"]) and (
        bool(event["new_device"]) or _is_unusual_country(event)
    ):
        return {
            "severity": "high",
            "classification": "possible_valid_account_abuse",
            "attack_hypothesis": (
                "The login succeeded but the surrounding context is unusual "
                "for the account."
            ),
            "mitre_techniques": ["T1078 - Valid Accounts"],
            "reasons": reasons,
        }

    if reasons:
        return {
            "severity": "medium",
            "classification": "needs_review",
            "attack_hypothesis": "The event is not clearly malicious but should be reviewed.",
            "mitre_techniques": [],
            "reasons": reasons,
        }

    return {
        "severity": "low",
        "classification": "routine_activity",
        "attack_hypothesis": "The event matches expected behavior.",
        "mitre_techniques": [],
        "reasons": ["no suspicious indicators were found"],
    }


@ai_function(
    name="get_auth_overview",
    description="Return a structured overview of the sample authentication log dataset.",
)
def get_auth_overview() -> Dict[str, object]:
    suspicious_events = []
    for event in AUTH_EVENTS:
        assessment = _classify_event(event)
        if assessment["classification"] != "routine_activity":
            suspicious_events.append(
                {
                    "event_id": event["event_id"],
                    "user": event["user"],
                    "classification": assessment["classification"],
                    "severity": assessment["severity"],
                }
            )

    return {
        "total_events": len(AUTH_EVENTS),
        "users": sorted({str(event["user"]) for event in AUTH_EVENTS}),
        "events_by_result": dict(Counter(str(event["result"]) for event in AUTH_EVENTS)),
        "events_by_protocol": dict(Counter(str(event["protocol"]) for event in AUTH_EVENTS)),
        "suspicious_events": suspicious_events,
    }


@ai_function(
    name="summarize_user_activity",
    description="Summarize one user's authentication history from the sample log dataset.",
)
def summarize_user_activity(
    username: Annotated[
        str,
        Field(description="User name to inspect. Must be one of: alice, bob, charlie, admin."),
    ],
) -> Dict[str, object]:
    user_events = [event for event in AUTH_EVENTS if event["user"] == username]
    if not user_events:
        return {
            "ok": False,
            "error": "user_not_found",
            "message": "User not found. Available users: alice, bob, charlie, admin.",
        }

    suspicious_events = []
    for event in user_events:
        assessment = _classify_event(event)
        if assessment["classification"] != "routine_activity":
            suspicious_events.append(
                {
                    "event_id": event["event_id"],
                    "classification": assessment["classification"],
                    "severity": assessment["severity"],
                }
            )

    return {
        "ok": True,
        "user": username,
        "total_events": len(user_events),
        "successful_logins": sum(1 for event in user_events if event["result"] == "success"),
        "failed_logins": sum(1 for event in user_events if event["result"] == "failure"),
        "countries": sorted({str(event["source_country"]) for event in user_events}),
        "protocols": sorted({str(event["protocol"]) for event in user_events}),
        "suspicious_events": suspicious_events,
    }


@ai_function(
    name="assess_event_risk",
    description="Assess whether one authentication event looks routine or suspicious.",
)
def assess_event_risk(
    event_id: Annotated[
        str,
        Field(description="Event identifier to assess, for example evt-1004."),
    ],
) -> Dict[str, object]:
    event = _find_event(event_id)
    if event is None:
        return {
            "ok": False,
            "error": "event_not_found",
            "message": "Event not found. Available IDs range from evt-1001 to evt-1008.",
        }

    assessment = _classify_event(event)
    return {
        "ok": True,
        "event_id": event["event_id"],
        "user": event["user"],
        "source_country": event["source_country"],
        "protocol": event["protocol"],
        "result": event["result"],
        "failed_attempts_10m": event["failed_attempts_10m"],
        "off_hours": event["off_hours"],
        "new_device": event["new_device"],
        "severity": assessment["severity"],
        "classification": assessment["classification"],
        "attack_hypothesis": assessment["attack_hypothesis"],
        "mitre_techniques": assessment["mitre_techniques"],
        "reasons": assessment["reasons"],
    }


base_url = os.getenv("API_BASE_URL")
api_key = os.getenv("API_KEY")
model_id = os.getenv("MODEL", "openai/gpt-oss-20b")

if not api_key:
    raise RuntimeError(
        "API_KEY is not set. Set it in your .env file or docker compose environment."
    )

client = OpenAIChatClient(
    base_url=base_url,
    api_key=api_key,
    model_id=model_id,
)

agent = client.create_agent(
    name="Authentication Log Explainer Agent",
    instructions="""
        You are an authentication log explanation agent.
        Your job is to help the user understand a small set of login events,
        explain which patterns look routine, and identify events that may
        resemble brute force or valid-account abuse.

        You have three tools:
        - get_auth_overview: use it when the user asks what data is available
          or wants a high-level summary.
        - summarize_user_activity: use it when the user asks about one user's
          login history or suspicious activity.
        - assess_event_risk: use it when the user asks whether a specific
          event looks suspicious.

        Rules:
        1) Always use the tools for questions about the dataset, users, or events.
        2) Do not invent events or users that are not present in the tool output.
        3) Treat ATT&CK mappings as hypotheses, not proof.
        4) Keep answers short, technical, and easy to follow.
        5) Always answer in English.
    """,
    tools=[
        get_auth_overview,
        summarize_user_activity,
        assess_event_risk,
    ],
)
