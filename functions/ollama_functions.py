from ollama import chat
from pydantic import BaseModel
from pprint import pprint
import json
import markdown
from config import ollama_model, ollama_keepalive


security_role = "You are a security expert, your task is to take alert data and respond to the question of the user"


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
        # "alert_recomedation": "Alert Recomendation",
        "verdict": "Verdict",
        "summary": "Summary",
    }
    for key in list(data.keys()):  # Use list to avoid runtime error
        if key in key_rename:
            data[key_rename[key]] = data.pop(key)
    return data


def prioritise_alert(alert=None):
    class elastic_alert(BaseModel):
        alert_url: str
        prority: int
        alert_name: str
        # alert_recomedation: str
        verdict: str
        summary: str

    security_role = """
You are a cybersecurity analyst performing alert triage. Analyze the security alert provided and respond with a JSON object using the exact following structure:

{
    "alert_url": "string containing the URL or reference ID of the alert",
    "priority": "integer between 1-10, where 1 is highest priority",
    "alert_name": "string containing the name/title of the alert",
    "verdict": "string containing either 'true_positive', 'false_positive', or 'undetermined'",
    "summary": "string containing a clear, concise analysis of the alert including key indicators and rationale for the verdict and priority"
}

Guidelines:
- Priority must be an integer from 1-10
- Verdict must be exactly one of: 'true_positive', 'false_positive', or 'undetermined'
- If critical information is missing, use 'undetermined' as verdict and explain what additional data is needed in the summary
- Do not make assumptions about missing data
- Ensure the output is valid JSON format
- Do not include any text outside of the JSON structure

Respond only with the JSON object. Do not include any additional commentary.
"""
    messages = [
        {
            "role": "system",
            "content": security_role,
        },
        {
            "role": "user",
            "content": f"""
                    Check the given alert for investigation priority, where 1 is the highest priority and 10 is the lowest.
                    Using the data you got make a verdict on if the alert is a true, false positive or unknown, do not elaborate on the verdict.
                    Write a summary of the attack story and what happened in detail and what could be done to investigate further, for powershell alerts, check the command that was executed and make an evaluation of that command.
                    Make sure that the output is a valid JSON object.

                    Alert Context:
                    {alert}""",
        },
    ]
    response = chat(
        messages=messages,
        keep_alive=ollama_keepalive,
        model=ollama_model,
        format=elastic_alert.model_json_schema(),
        options={
            "num_predict": -1,
            "num_ctx": 20000,
            # "temperature": temperature,
        },
    )
    response = json.loads(response.message.content)
    response = rename_keys(response)
    return response


def evaluate_priorisation(alert=None, evaluation=None):
    class true_false(BaseModel):
        satisfactory: bool
        satiscfaction_level: int

    messages = [
        {
            "role": "system",
            "content": security_role,
        },
        {
            "role": "user",
            "content": f"""Given the original alert data and its summary, assess whether the summary accurately and concisely captures the key points of the original alert."
            "Provied a true or false answer if you think the summary is satisfactory and could be published to the user as well as a score from 1-10 on how satisfied you are with the summary."
            Original Text:
            {alert}
            Summary:
            {evaluation}""",
        },
    ]
    response = chat(
        messages=messages,
        model=ollama_model,
        format=true_false.model_json_schema(),
        keep_alive=ollama_keepalive,
        options={
            "num_predict": -1,
            "num_ctx": 10000,
            # "temperature": temperature,
        },
    )
    response = json.loads(response.message.content)
    return response


def prioritise_alerts(alerts=None, html=False):
    if alerts:
        evaluated = []
        for alert in alerts:
            evaluations = 1
            storage = []
            while True:
                evaluation = prioritise_alert(alert=alert)
                check = evaluate_priorisation(alert=alert, evaluation=evaluation)
                if check["satisfactory"]:
                    break
                else:
                    print("Re-evaluating the alert")
                    print(f"Attempt: {evaluations}")
                    storage.append(
                        {
                            "evaluation": evaluation,
                            "satisfaction_level": check["satiscfaction_level"],
                        }
                    )
                    if evaluations >= 3:
                        evaluations += 1
                        print(
                            "Too many attempts, skipping re-generation and taking the best result"
                        )
                        evaluation = sorted(
                            storage, key=lambda x: x["satisfaction_level"], reverse=True
                        )[0]["evaluation"]
                        break

            if html:
                for key in evaluation:
                    evaluation[key] = convert_md_to_html(evaluation[key])
            evaluated.append(evaluation)
        return evaluated


def investigate_alert(alert):
    if alert:

        messages = [
            {
                "role": "system",
                "content": security_role,
            },
            {
                "role": "user",
                "content": f"""Help the security engineer understand what to do with the presented alert. If possible give feedback on if it is a true or false positive. {alert}""",
            },
        ]
        response = chat(
            messages=messages,
            model=ollama_model,
            keep_alive=ollama_keepalive,
            options={
                "num_predict": -1,
                "num_ctx": 10000,
                # "temperature": temperature,
            },
        )
        return response.message.content


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


def evaluate_email(
    subject=None,
    date=None,
    text_plain=None,
    text_html=None,
    headers=None,
    attachments=None,
):

    messages = [
        {
            "role": "system",
            "content": security_role,
        },
        {
            "role": "user",
            "content": f"""Help the security engineer Analyse this Email and give feedback on if it is a true or false positive.
            The email has the following subject: {subject}
            The email was sent on: {date}
            The email has the following plain text: {text_plain}
            The email has the following headers: {headers}
            The email has the following attachments: {attachments}
            """,
        },
    ]
    response = chat(
        messages=messages,
        model=ollama_model,
        keep_alive=ollama_keepalive,
        options={
            "num_predict": -1,
            "num_ctx": 10000,
            # "temperature": temperature,
        },
    )
    return response.message.content
