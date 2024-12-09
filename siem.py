from functions.elastic import ElasticSIEM
from config import (
    elastic_config,
    confluence_page_id,
    confluence_token,
    confluence_url,
    confluence_page_name,
)
from functions.ollama_functions import (
    prioritise_alerts,
    evaluate_suricata,
    investigate_alert,
)
from functions.confluence import confluence_update_page
from atlassian import Confluence
from pprint import pprint
import json
import argparse
from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown
import winsound
import pandas as pd
from tabulate import tabulate

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


def convert_to_markdown_table(data=None, escape=True, transpose_table=False):
    df = pd.DataFrame(data)
    if transpose_table:
        markdown_table = tabulate(
            df.T, headers="keys", tablefmt="github", showindex=False
        )
    else:
        markdown_table = tabulate(
            df, headers="keys", tablefmt="github", showindex=False
        )
    return markdown_table


def output_confluence(hours=None, size=None):
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


def output_md(hours=None, size=None, path=None):
    if path:
        alerts = es.get_latest_alerts(hours=hours, size=size)
        priorities = prioritise_alerts(alerts=alerts, html=False)
        table = convert_to_markdown_table(data=priorities)
        with open(path, "w") as f:
            f.write(table)
    else:
        console.print("Please provide a path to save the markdown file.")


def output_console(hours=None, size=None):
    alerts = es.get_latest_alerts(hours=hours, size=size)
    priorities = prioritise_alerts(alerts=alerts, html=False)
    format_table(priorities)


def main():
    parser = argparse.ArgumentParser(description="Process some integers.")
    parser.add_argument("--prioritise_alerts", action="store_true")
    parser.add_argument("--evaluate_suricata", action="store_true")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--size", type=int, default=10)
    parser.add_argument("--investigate", type=str)
    parser.add_argument(
        "--output", type=str, choices=["confluence", "md", "console"], required=True
    )
    parser.add_argument("--path", type=str, help="Path to save the markdown file")
    args = parser.parse_args()
    hours = args.hours
    size = args.size

    if args.prioritise_alerts:
        if args.output == "confluence":
            output_confluence(hours=hours, size=size)
        elif args.output == "md":
            output_md(hours=hours, size=size, path=args.path)
        elif args.output == "console":
            output_console(hours=hours, size=size)

        winsound.Beep(440, 500)
    elif args.evaluate_suricata:
        alerts = es.get_latest_alerts(hours=hours, size=size, module="suricata")
        evaluate_suricata(alerts=alerts, size=size, hours=hours)
        # evaluate_suricata(size=args.size, hours=args.hours)
    elif args.investigate:
        alert = es.get_alert(args.investigate)
        response = investigate_alert(alert)
        console.print(Markdown(response))


if __name__ == "__main__":
    main()
