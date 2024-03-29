from siem.elastic import ElasticSIEM
from config import elastic_config
from llm.openai import OpenAIWrapper
from pprint import pprint
import json


es = ElasticSIEM(
    hosts=elastic_config["hosts"],
    username=elastic_config["username"],
    password=elastic_config["password"],
)

def prioritise_alerts(hours=24, size=10):
    alerts = es.get_latest_alerts(hours=hours, size=size)
    evaluated = []
    for alert in alerts:
        retry_count = 0
        retry_times = 2
        while retry_count <= retry_times:
            # x = alert
            # x["kibana.alert.rule.parameters"].pop("risk_score", None)
            # x["kibana.alert.rule.parameters"].pop("severity_mapping", None)
            # x["kibana.alert.rule.parameters"].pop("severity", None)
            openai_wrapper = OpenAIWrapper()
            messages = [
                {
                    "role": "system",
                    "content": "You are a security expert, your task is to take alert data and respond to the question of the user",
                },
                {
                    "role": "user",
                    "content": f"""Check the alert severity, give a the alert severity has to be a number of 1-10 while 1 is lowest and 10 is highest, return as a JSON with this format: {{ "alert_name": "<alert name>", "alert_severity": "<severity>", "comment": "<comment>" }}: {alert}""",
                },
            ]
            text = openai_wrapper.generate_text(messages=messages, max_tokens=6000)
            try:
                answer = json.loads(text)
                # pprint(answer)
                evaluated.append(
                    {
                        "alert_url": alert["alert_url"],
                        "llm": answer,
                    }
                )
                break
            except:
                retry_count += 1
                print("Retry")
                pprint(alert)
                print(text)
                if retry_count >= retry_times:
                    evaluated.append(
                        {
                            "alert_url": alert["alert_url"],
                            "error": "Unable to process via LLM",
                        }
                    )
    pprint(evaluated)

def evaluate_suricata(size=10, hours=24):
    alerts = es.get_latest_alerts(hours=hours, size=size, module="suricata")
    for alert in alerts:
        print(f'Payload:\n{alert["suricata_payload_printable"]}')
        print(alert["suricata_signature"])
        print(alert["suricata_signature_id"])
        openai_wrapper = OpenAIWrapper()
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
        text = openai_wrapper.generate_text(messages=messages, max_tokens=6000)
        print(text)
        quit()


def main():
    #prioritise_alerts()
    evaluate_suricata()


if __name__ == "__main__":
    main()