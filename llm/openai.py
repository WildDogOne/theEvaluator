import openai
import json
from pprint import pprint


class OpenAIWrapper:
    def __init__(
        self, api_key="your_openai_api_key", base_url="http://localhost:5000/v1/"
    ):
        openai.api_key = api_key
        openai.base_url = base_url

    def generate_text(self, messages, max_tokens=400):
        response = openai.chat.completions.create(
            model="text-davinci-002", messages=messages, max_tokens=max_tokens
        )
        return response.choices[0].message.content

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

    def prioritise_alerts(self, alerts=None, hours=24, size=10):
        # alerts = es.get_latest_alerts(hours=hours, size=size)
        if alerts:
            evaluated = []
            for alert in alerts:
                retry_count = 0
                retry_times = 2
                while retry_count <= retry_times:
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
                    text = self.generate_text(messages=messages, max_tokens=6000)
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
            return evaluated
