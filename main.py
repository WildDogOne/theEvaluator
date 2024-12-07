from functions.elastic import ElasticSIEM
from config import (
    elastic_config,
    confluence_page_id,
    confluence_token,
    confluence_url,
    confluence_page_name,
)
from functions.ollama_functions import prioritise_alerts, evaluate_suricata
from functions.confluence import confluence_update_page
from atlassian import Confluence
from pprint import pprint
import json
import argparse
from rich.console import Console
from rich.table import Table

console = Console()

es = ElasticSIEM(
    hosts=elastic_config["hosts"],
    username=elastic_config["username"],
    password=elastic_config["password"],
)


def format_table(data):
    table = Table(title="Alerts")
    if not data:
        console.print("No alerts to display.")
        return

    # Add columns based on keys from the first dictionary in the list
    for key in data[0].keys():
        table.add_column(key, style="cyan", no_wrap=True)

    # Add rows based on each dictionary in the list
    for dataset in data:
        table.add_row(*(str(value) for value in dataset.values()))

    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Process some integers.")
    parser.add_argument("--prioritise_alerts", action="store_true")
    parser.add_argument("--evaluate_suricata", action="store_true")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--size", type=int, default=10)
    args = parser.parse_args()
    hours = args.hours
    size = args.size

    if args.prioritise_alerts:
        alerts = es.get_latest_alerts(hours=hours, size=size)
        priorities = prioritise_alerts(alerts=alerts, html=True)
        # pprint(priorities)
        # format_table(priorities)
        # prioritise_alerts(hours=args.hours, size=args.size)
        confluence = Confluence(url=confluence_url, token=confluence_token)
        confluence_update_page(
            confluence=confluence,
            title=confluence_page_name,
            parent_id=confluence_page_id,
            table=priorities,
            representation="storage",
            full_width=False,
            escape_table=False,
        )
    elif args.evaluate_suricata:
        alerts = es.get_latest_alerts(hours=hours, size=size, module="suricata")
        evaluate_suricata(alerts=alerts, size=size, hours=hours)
        # evaluate_suricata(size=args.size, hours=args.hours)


if __name__ == "__main__":
    main()
