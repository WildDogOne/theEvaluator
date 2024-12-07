from ollama import chat
from pydantic import BaseModel
from pprint import pprint
import json
import markdown


class elastic_alert(BaseModel):
    alert_url: str
    prority: int
    alert_name: str
    alert_severity: int
    alert_recomedation: str


def convert_md_to_html(md):
    if isinstance(md, str):
        md = md.replace("\n", "<br/>")
        return markdown.markdown(md)
    else:
        return md


def rename_keys(data):
    key_rename = {
        "alert_url": "Alert URL",
        "prority": "Priority",
        "alert_name": "Alert Name",
        "alert_severity": "Alert Severity",
        "alert_recomedation": "Alert Recomendation",
    }
    for key in list(data.keys()):  # Use list to avoid runtime error
        if key in key_rename:
            data[key_rename[key]] = data.pop(key)
    pprint(data)
    return data


def prioritise_alerts(alerts=None, html=False):
    if alerts:
        evaluated = []
        for alert in alerts:
            # pprint(alert)

            messages = [
                {
                    "role": "system",
                    "content": "You are a security expert, your task is to take alert data and respond to the question of the user",
                },
                {
                    "role": "user",
                    "content": f"""Check the alert severity, give a the alert severity has to be a number of 1-10 while 1 is lowest and 10 is highest.
                    Also give a recomendation of what could be done to triage this alert further: {alert}""",
                },
            ]
            response = chat(
                messages=messages,
                model="qwq",
                format=elastic_alert.model_json_schema(),
            )
            response = json.loads(response.message.content)
            response = rename_keys(response)
            if html:
                for key in response:
                    response[key] = convert_md_to_html(response[key])
            evaluated.append(response)
        return evaluated


def evaluate_suricata(self, alerts=None, size=10, hours=24):
    if alerts:
        for alert in alerts:
            print(f'Payload:\n{alert["suricata_payload_printable"]}')
            print(alert["suricata_signature"])
            print(alert["suricata_signature_id"])

            messages = [
                {
                    "role": "system",
                    "content": "You are a helpful, expert assistant who answers questions about Security. Do not answer questions unrelated to Security. Use the following context to answer questions:",
                },
                {
                    "role": "user",
                    "content": f"""Explain the suricata alert {alert["suricata_signature"]} with the following payload and suggest possible counter meassures: {alert["suricata_payload_printable"]}""",
                },
            ]
            text = self.generate_text(messages=messages, max_tokens=6000)
            print(text)
            quit()
    else:
        print("No alerts to evaluate")
        quit()
