"""Repair support: AI functions append verifier errors and ask for a corrected answer.

Module 1's graph runs the loop (max MAX_REPAIRS); after that the claim stays verified=false.
"""

MAX_REPAIRS = 2


def with_repair(messages: list[dict], previous_errors: list[str] | None) -> list[dict]:
    if not previous_errors:
        return messages
    listing = "\n".join(f"- {error}" for error in previous_errors)
    return [
        *messages,
        {
            "role": "user",
            "content": "Your previous answer failed verification by plain code:\n"
            f"{listing}\nReturn a corrected answer. Use only facts present in the supplied "
            "evidence and list every fact you mention in facts_used.",
        },
    ]
