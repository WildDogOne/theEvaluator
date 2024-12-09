# theEvaluator

A tool collection to utilise local (or remote) LLMs to help triage security alerts

## Phishing
### Usage
```powershell
python theEvaluator.py --eml <path_to_phishing_file>
```

## siem.py
### Configuration

The script relies on configuration details found in `config.py`. Ensure you have the following
variables properly configured:

```python
elastic_config = {
    "hosts": ["your_elastic_host"],
    "username": "your_username",
    "password": "your_password"
}

confluence_page_id = "your_confluence_page_id"
confluence_token = "your_confluence_token"
confluence_url = "https://your-confluence-url.com"
confluence_page_name = "Your Confluence Page Name"
```
#### Options

- `--prioritise_alerts`: Prioritize and output alerts.
  - `--hours`: Number of hours to look back for alerts (default: 24).
  - `--size`: Maximum number of alerts to retrieve (default: 10).
  - `--output`: Output destination ("confluence", "md", or "console").
    - For output `"md"`, you must also specify the path using `--path`.
- `--evaluate_suricata`: Evaluate Suricata alerts.
  - `--hours` and `--size` options apply similarly as for prioritizing alerts.
- `--investigate <alert_id>`: Investigate a specific alert by its ID.
#### Examples

1. **Prioritize Alerts to Confluence Page**

```bash
python siem.py --prioritise_alerts --output confluence
```

2. **Save Prioritized Alerts as Markdown File**

```bash
python siem.py --prioritise_alerts --output md --path path/to/file.md
```

3. **Display Prioritized Alerts in Console**

```bash
python siem.py --prioritise_alerts --output console
```

4. **Evaluate Suricata Alerts**

```bash
python siem.py --evaluate_suricata
```

5. **Investigate Specific Alert by ID**

```bash
python siem.py --investigate <alert_id>
```
