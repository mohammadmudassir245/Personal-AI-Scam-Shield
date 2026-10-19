from __future__ import annotations


def recommend(scam_type: str, techniques: dict, has_url: bool, risk_level: str) -> tuple[str, str]:
    cred = techniques.get("credential", {}).get("matched")
    reward = techniques.get("reward", {}).get("matched")
    financial = techniques.get("financial", {}).get("matched")
    lowered = scam_type.lower()

    if risk_level == "LOW":
        return (
            "Looks relatively ordinary",
            "No strong scam pattern was found. If anything still feels off, open the official app or website yourself instead of using a link from the message.",
        )

    if "otp" in lowered or cred:
        return (
            "Do not share codes or passwords",
            "Never share an OTP, PIN, CVV, or password. Legitimate organizations will not ask for them by SMS, chat, or email. If a bank or app is mentioned, open that official app yourself and check there.",
        )
    if "bank" in lowered or "account takeover" in lowered or "phishing" in lowered:
        return (
            "Skip the link - use the official app",
            "Do not tap the link or enter login details. Open your bank or service from the official app or by typing the known website address yourself. Call the number on the back of your card if you need to confirm.",
        )
    if "prize" in lowered or reward:
        return (
            "Ignore unexpected prizes",
            "Do not pay a fee or share bank details to claim a prize you did not enter. Unexpected winnings that require a click or payment are a common scam.",
        )
    if "job" in lowered:
        return (
            "Do not pay to get a job",
            "Real employers do not ask for registration fees, interview fees, or OTPs. Verify the company through its official career page.",
        )
    if "investment" in lowered or financial:
        return (
            "Do not send money under pressure",
            "Pause any transfer, UPI request, gift-card purchase, or investment pitch from this message. Confirm through a known official channel, not a number or link in the text.",
        )
    if "delivery" in lowered:
        return (
            "Check tracking in the official app",
            "Do not pay a customs or delivery fee from a random link. Open the courier's official app or website and track the parcel there.",
        )
    if "government" in lowered:
        return (
            "Use official government portals only",
            "Do not submit Aadhaar, PAN, or tax details from this message. Use the official government website or app you already know, typed by you.",
        )
    if has_url:
        return (
            "Do not use this link to sign in",
            "Avoid entering credentials until you have opened the service through a saved bookmark or official app. Hover or inspect the domain if you are unsure.",
        )
    return (
        "Pause and verify independently",
        "Do not follow instructions from this message. Contact the organization using a phone number or app you already trust — not one provided here.",
    )
