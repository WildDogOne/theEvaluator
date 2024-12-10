from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
from pprint import pprint


class ElasticSIEM:
    def __init__(
        self,
        hosts="your_host",
        username="your_username",
        password="your_password",
        verify_certs=False,
    ):
        print(hosts)
        self.es = Elasticsearch(
            hosts=hosts,
            http_auth=(username, password),
            verify_certs=verify_certs,
        )

    def get_latest_alerts(
        self, index="*.alerts-security.*", size=10, hours=24, module=None
    ):
        now = datetime.utcnow()
        hours_ago = now - timedelta(hours=hours)
        body = {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": True,
            "query": {
                "bool": {
                    "must": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": hours_ago.isoformat(),
                                    "lte": now.isoformat(),
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "must_not": [
                        {"match": {"message": "Potentially Bad Traffic"}},
                        {"match": {"message": "Misc Attack"}},
                        {
                            "match": {
                                "kibana.alert.rule.name": "Multiple Alerts in Different ATT&CK Tactics on a Single Host"
                            }
                        },
                    ],
                }
            },
        }
        if module:
            body["query"]["bool"]["must"].append(
                {"match": {"kibana.alert.original_event.module": module}}
            )
        response = self.es.search(index=index, body=body)
        important_information = []
        for hit in response["hits"]["hits"]:
            hit = hit["_source"]
            info = {}
            if (
                "kibana.alert.rule.parameters" in hit
                and "description" in hit["kibana.alert.rule.parameters"]
            ):
                info["description"] = hit["kibana.alert.rule.parameters"]["description"]
            if "kibana.alert.reason" in hit:
                info["reason"] = hit["kibana.alert.reason"]
            if "kibana.alert.rule.description" in hit:
                info["rule_description"] = hit["kibana.alert.rule.description"]
            if "kibana.alert.url" in hit:
                info["alert_url"] = hit["kibana.alert.url"]
            fieldlist = [
                "rule",
                "source",
                "destination",
                "process.executable",
                "winlog.event_data.TaskContent",
                "powershell.file.script_block_text",
            ]
            for x in fieldlist:
                if x in hit:
                    info[x] = hit[x]
            # Suricata Specific Fields to add
            if "suricata" in hit and "eve" in hit["suricata"]:
                info["suricata_category"] = hit["suricata"]["eve"]["alert"]["category"]
                info["suricata_signature"] = hit["suricata"]["eve"]["alert"][
                    "signature"
                ]
                info["suricata_signature_id"] = hit["suricata"]["eve"]["alert"][
                    "signature_id"
                ]
                fieldlist = ["direction", "dns", "flow", "payload_printable"]
                for x in fieldlist:
                    if x in hit["suricata"]["eve"]:
                        info[f"suricata_{x}"] = hit["suricata"]["eve"][x]
            # important_information.append(info)
            important_information.append(hit)

        return important_information

    def get_alert(self, id):
        body = {
            "_source": True,
            "query": {
                "bool": {
                    "must": [
                        {"match": {"_id": id}},
                    ]
                }
            },
        }
        response = self.es.search(
            index=".internal.alerts-security.alerts-default-*", body=body
        )
        if response["hits"]["total"]["value"] == 0:
            return None
        else:
            return response["hits"]["hits"][0]
