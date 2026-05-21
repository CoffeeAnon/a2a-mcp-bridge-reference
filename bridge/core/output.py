import json
import xml.etree.ElementTree as ET
from typing import Any


def to_xml(command: str, items: list[dict], meta: dict[str, Any]) -> str:
    root = ET.Element("result")

    meta_el = ET.SubElement(root, "meta")
    ET.SubElement(meta_el, "command").text = command
    for key, value in meta.items():
        if key == "command":
            continue  # already written above
        ET.SubElement(meta_el, key).text = str(value)

    items_el = ET.SubElement(root, "items")
    for item in items:
        item_el = ET.SubElement(items_el, "item")
        for key, value in item.items():
            ET.SubElement(item_el, key).text = str(value)

    return ET.tostring(root, encoding="unicode")


def to_human(command: str, items: list[dict], meta: dict[str, Any]) -> str:
    # Lean format: items only. The meta block (command name, status, count, echoed
    # kwargs) tells the caller nothing it doesn't already know, and every token
    # counts when this output is fed to a small LLM as a tool response.
    lines = []
    for item in items:
        lines.append(", ".join(f"{k}={v}" for k, v in item.items()))
    if not lines:
        lines.append("(no results)")
    return "\n".join(lines)


def error_xml(
    command: str, status: int | str, message: str, context: dict | None = None
) -> str:
    root = ET.Element("error")
    ET.SubElement(root, "command").text = command
    ET.SubElement(root, "status").text = str(status)
    ET.SubElement(root, "message").text = message
    for key, value in (context or {}).items():
        ET.SubElement(root, key).text = str(value)
    return ET.tostring(root, encoding="unicode")


def error_human(
    command: str, status: int | str, message: str, context: dict | None = None
) -> str:
    lines = [f"Error in {command} ({status}): {message}"]
    for key, value in (context or {}).items():
        lines.append(f"  {key}: {value}")
    return "\n".join(lines)


def approval_required_xml(command: str, args: dict[str, str]) -> str:
    root = ET.Element("approval_required")
    ET.SubElement(root, "command").text = command
    args_el = ET.SubElement(root, "args")
    for key, value in args.items():
        ET.SubElement(args_el, key).text = str(value)
    return ET.tostring(root, encoding="unicode")


def approval_required_json(command: str, args: dict[str, str]) -> str:
    return json.dumps({
        "approval_required": True,
        "command": command,
        "args": args,
    })
