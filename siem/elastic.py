from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
from pprint import pprint


class ElasticSIEM:
    def __init__(
        self,
        hosts="your_host",
        username="your_username",
        password="your_password",
        verify_verts=False,
    ):
        print(hosts)
        self.es = Elasticsearch(
            hosts=hosts,
            http_auth=(username, password),
            # ca_certs=False
            verify_certs=verify_verts,
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
                        # {"match": {"kibana.alert.original_event.module": "suricata"}},
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
            # pprint(hit)
            # quit()
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
            fieldlist = ["rule", "source", "destination"]
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
            important_information.append(info)

        return important_information
