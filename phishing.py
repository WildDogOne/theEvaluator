from pprint import pprint
import json
import argparse
from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown
import datetime
import json
from fast_mail_parser import parse_email, ParseError
from functions.ollama_functions import evaluate_email


console = Console()


def json_serial(obj):
    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial


def parse_eml(eml):
    with open(eml, "r") as f:
        raw_email = f.read()

    try:
        email = parse_email(raw_email)
    except ParseError as e:
        print("Failed to parse email: ", e)
        quit(1)
    subject = email.subject
    date = email.date
    text_plain = email.text_plain
    text_html = email.text_html
    headers = email.headers
    attachments = []
    for attachment in email.attachments:
        # print(attachment.mimetype)
        # print(attachment.content)
        # print(attachment.filename)
        attachments.append(attachment.filename)

    response = evaluate_email(
        subject=subject,
        date=date,
        text_plain=text_plain,
        text_html=text_html,
        headers=headers,
        attachments=attachments,
    )
    pprint(response)


def main():
    parser = argparse.ArgumentParser(description="Process some integers.")
    parser.add_argument("--eml", type=str, help="Path to EML file")
    args = parser.parse_args()
    eml = args.eml
    if eml:
        parse_eml(eml)
    else:
        console.print("Please provide a path to the EML file.")


if __name__ == "__main__":
    main()
